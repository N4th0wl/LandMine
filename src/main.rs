use anyhow::Result;
use clap::Parser;
use std::{
    path::{Path, PathBuf},
    thread,
    time::Duration,
};

use landmine::{
    app::{DefenseOptions, Monitor},
    cli::Args,
    detector::{custom_rules, RuleEngine},
    enrich::HashDb,
    logger::{ConsoleOptions, EventSink, RotatingWriter, WinEventLogger},
    models::Severity,
    platform,
};

fn main() -> Result<()> {
    let args = Args::parse();

    let (engine, rule_count) = build_engine(&args)?;

    // Muat Threat Intel Hash DB jika ada
    let hash_db = if Path::new(&args.hash_db).exists() {
        HashDb::load_file(&args.hash_db)?
    } else {
        HashDb::new()
    };
    let hash_count = hash_db.len();

    let color = !args.no_color && std::env::var_os("NO_COLOR").is_none() && platform::enable_ansi();

    // Tampilkan CLI UI Banner & Usage
    eprint!(
        "{}",
        landmine::logger::render_banner(&args, rule_count, hash_count, color)
    );

    let writer = RotatingWriter::open(
        &args.out,
        args.max_size_mb.saturating_mul(1024 * 1024),
        args.max_backups,
    )?;
    let winevent_logger = if args.winevent {
        Some(WinEventLogger::new("LandMine"))
    } else {
        None
    };

    let mut sink = EventSink::new(
        writer,
        ConsoleOptions {
            format: args.format,
            color,
            // Console hanya menampilkan temuan yang layak diperhatikan.
            min_severity: Severity::Medium,
        },
        winevent_logger,
    );

    let defense_opts = DefenseOptions {
        suspend_on_high: args.suspend_on_high,
        kill_on_critical: args.kill_on_critical,
        quarantine_dir: args.dump_quarantine.map(PathBuf::from),
    };

    let mut monitor = Monitor::new(engine)
        .with_hash_db(hash_db)
        .with_defense(defense_opts);

    let interval = Duration::from_secs(args.interval.max(1));
    let mut cycle: u64 = 0;

    loop {
        cycle += 1;
        let mut alert_count = 0;

        for evt in monitor
            .tick()?
            .iter()
            .filter(|e| e.severity >= args.min_severity)
        {
            sink.emit(evt)?;
            if evt.severity >= Severity::Medium {
                alert_count += 1;
            }
        }

        if args.once {
            if alert_count == 0 && args.format == landmine::logger::ConsoleFormat::Pretty {
                let c_green = if color { "\x1b[1;32m" } else { "" };
                let c_reset = if color { "\x1b[0m" } else { "" };
                eprintln!("\n{c_green}  [✓] Baseline snapshot complete. No high-severity threats detected.{c_reset}\n");
            }
            break;
        }

        if args.format == landmine::logger::ConsoleFormat::Pretty {
            let ts = chrono::Utc::now().format("%H:%M:%S");
            let c_dim = if color { "\x1b[2m" } else { "" };
            let c_cyan = if color { "\x1b[1;36m" } else { "" };
            let c_reset = if color { "\x1b[0m" } else { "" };
            eprintln!(
                "{c_dim}  [{ts}] {c_cyan}●{c_reset}{c_dim} Live monitor standing guard (cycle #{cycle} | interval {}s){c_reset}",
                args.interval
            );
        }

        thread::sleep(interval);
    }

    sink.shutdown();
    Ok(())
}

fn build_engine(args: &Args) -> Result<(RuleEngine, usize)> {
    let engine = RuleEngine::from_allowlist_file(&args.allowlist);

    if !Path::new(&args.rules).exists() {
        return Ok((engine, 0));
    }

    // File rules yang rusak harus gagal keras, bukan diabaikan diam-diam.
    let rules = custom_rules::load_rules(&args.rules)?;
    let count = rules.len();
    Ok((engine.with_custom_rules(rules), count))
}
