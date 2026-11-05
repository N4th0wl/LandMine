use anyhow::Result;
use std::{
    sync::mpsc::{self, RecvTimeoutError, Sender},
    thread::{self, JoinHandle},
    time::Duration,
};

use super::{
    console::{self, ConsoleFormat},
    jsonl::RotatingWriter,
    winevent::WinEventLogger,
};
use crate::models::{ProcEvent, Severity};

#[derive(Debug, Clone, Copy)]
pub struct ConsoleOptions {
    pub format: ConsoleFormat,
    pub color: bool,
    /// Event dengan severity di bawah ini tidak dicetak ke console.
    pub min_severity: Severity,
}

/// Tujuan akhir event: file JSONL (ditulis oleh thread khusus lewat channel,
/// sehingga I/O disk tidak memblokir loop pengumpul), console, dan opsional Windows Event Log.
pub struct EventSink {
    tx: Option<Sender<String>>,
    handle: Option<JoinHandle<()>>,
    console: ConsoleOptions,
    winevent: Option<WinEventLogger>,
}

impl EventSink {
    pub fn new(
        mut writer: RotatingWriter,
        console: ConsoleOptions,
        winevent: Option<WinEventLogger>,
    ) -> Self {
        let (tx, rx) = mpsc::channel::<String>();

        let handle = thread::spawn(move || loop {
            match rx.recv_timeout(Duration::from_millis(500)) {
                Ok(line) => {
                    write_or_warn(&mut writer, &line);
                    // Tulis semua yang sudah antre, lalu flush satu kali.
                    for line in rx.try_iter() {
                        write_or_warn(&mut writer, &line);
                    }
                    if let Err(e) = writer.flush() {
                        eprintln!("[WARN] failed to flush log: {e}");
                    }
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => {
                    let _ = writer.flush();
                    break;
                }
            }
        });

        Self {
            tx: Some(tx),
            handle: Some(handle),
            console,
            winevent,
        }
    }

    pub fn emit(&self, evt: &ProcEvent) -> Result<()> {
        let line = serde_json::to_string(evt)?;

        if evt.severity >= self.console.min_severity {
            let rendered = match self.console.format {
                ConsoleFormat::Jsonl => line.clone(),
                ConsoleFormat::Pretty => console::render_pretty(evt, self.console.color),
            };
            println!("{rendered}");
            let _ = std::io::Write::flush(&mut std::io::stdout());
        }

        // Tulis ke Windows Event Log jika aktif dan severity >= Medium
        if let Some(ref wel) = self.winevent {
            if evt.severity >= Severity::Medium {
                wel.report(evt);
            }
        }

        if let Some(tx) = &self.tx {
            tx.send(line)
                .map_err(|_| anyhow::anyhow!("log writer thread has stopped"))?;
        }
        Ok(())
    }

    /// Menutup channel dan menunggu semua baris tertulis ke disk.
    pub fn shutdown(&mut self) {
        self.tx.take();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for EventSink {
    fn drop(&mut self) {
        self.shutdown();
    }
}

fn write_or_warn(writer: &mut RotatingWriter, line: &str) {
    if let Err(e) = writer.write_line(line) {
        eprintln!("[WARN] failed to write log line: {e}");
    }
}
