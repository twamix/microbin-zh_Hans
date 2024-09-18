extern crate core;

use chrono::{DateTime, Local, Utc};
use crate::args::ARGS;
use crate::endpoints::{
    admin, auth_admin, auth_upload, create, edit, errors, file, guide, list,
    pasta as pasta_endpoint, qr, remove, static_resources,
};
use crate::pasta::Pasta;
use crate::util::db::read_all;
use crate::util::telemetry::start_telemetry_thread;
use actix_web::middleware::Condition;
use actix_web::{middleware, web, App, HttpServer};
use actix_web_httpauth::middleware::HttpAuthentication;
use env_logger::Builder;
use log::LevelFilter;
use std::fs;
use std::io::Write;
use std::sync::Mutex;
use dotenv::dotenv;
use std::env;
use std::collections::HashMap;
use tokio::time::{self, Duration as TokioDuration};

pub mod args;
pub mod pasta;

pub mod util {
    pub mod animalnumbers;
    pub mod auth;
    pub mod db;
    pub mod db_json;
    pub mod db_sqlite;
    pub mod hashids;
    pub mod misc;
    pub mod syntaxhighlighter;
    pub mod telemetry;
    pub mod version;
}

pub mod endpoints {
    pub mod admin;
    pub mod auth_admin;
    pub mod auth_upload;
    pub mod create;
    pub mod edit;
    pub mod errors;
    pub mod file;
    pub mod guide;
    pub mod list;
    pub mod pasta;
    pub mod qr;
    pub mod remove;
    pub mod static_resources;
}

pub struct AppState {
    pub pastas: Mutex<Vec<Pasta>>,
    pub sessions: Mutex<HashMap<String, DateTime<Utc>>>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();
    let _tz = env::var("TZ").unwrap_or_else(|_| {
        println!("WARNING：未配置TZ环境变量");
        String::new()
    });
    let _admin_username = env::var("MICROBIN_ADMIN_USERNAME").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ADMIN_USERNAME环境变量");
        String::new()
    });
    let _admin_password = env::var("MICROBIN_ADMIN_PASSWORD").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ADMIN_PASSWORD环境变量");
        String::new()
    });
    let _editable = env::var("MICROBIN_EDITABLE").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_EDITABLE环境变量");
        String::new()
    });
    let _hide_header = env::var("MICROBIN_HIDE_HEADER").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_HIDE_HEADER环境变量");
        String::new()
    });
    let _hide_footer = env::var("MICROBIN_HIDE_FOOTER").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_HIDE_FOOTER环境变量");
        String::new()
    });
    let _hide_logo = env::var("MICROBIN_HIDE_LOGO").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_HIDE_LOGO环境变量");
        String::new()
    });
    let _no_listing = env::var("MICROBIN_NO_LISTING").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_NO_LISTING环境变量");
        String::new()
    });
    let _highlight_syntax = env::var("MICROBIN_HIGHLIGHTSYNTAX").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_HIGHLIGHTSYNTAX环境变量");
        String::new()
    });
    let _port = env::var("MICROBIN_PORT").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_PORT环境变量");
        String::new()
    });
    let _bind = env::var("MICROBIN_BIND").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_BIND环境变量");
        String::new()
    });
    let _private = env::var("MICROBIN_PRIVATE").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_PRIVATE环境变量");
        String::new()
    });
    let _pure_html = env::var("MICROBIN_PURE_HTML").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_PURE_HTML环境变量");
        String::new()
    });
    let _json_db = env::var("MICROBIN_JSON_DB").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_JSON_DB环境变量");
        String::new()
    });
    let _data_dir = env::var("MICROBIN_DATA_DIR").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_DATA_DIR环境变量");
        String::new()
    });
    let _show_read_stats = env::var("MICROBIN_SHOW_READ_STATS").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_SHOW_READ_STATS环境变量");
        String::new()
    });
    let _threads = env::var("MICROBIN_THREADS").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_THREADS环境变量");
        String::new()
    });
    let _gc_days = env::var("MICROBIN_GC_DAYS").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_GC_DAYS环境变量");
        String::new()
    });
    let _enable_burn_after = env::var("MICROBIN_ENABLE_BURN_AFTER").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ENABLE_BURN_AFTER环境变量");
        String::new()
    });
    let _default_burn_after = env::var("MICROBIN_DEFAULT_BURN_AFTER").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_DEFAULT_BURN_AFTER环境变量");
        String::new()
    });
    let _qr = env::var("MICROBIN_QR").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_QR环境变量");
        String::new()
    });
    let _eternal_pasta = env::var("MICROBIN_ETERNAL_PASTA").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ETERNAL_PASTA环境变量");
        String::new()
    });
    let _enable_readonly = env::var("MICROBIN_ENABLE_READONLY").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ENABLE_READONLY环境变量");
        String::new()
    });
    let _default_expiry = env::var("MICROBIN_DEFAULT_EXPIRY").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_DEFAULT_EXPIRY环境变量");
        String::new()
    });
    let _no_file_upload = env::var("MICROBIN_NO_FILE_UPLOAD").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_NO_FILE_UPLOAD环境变量");
        String::new()
    });
    let _wide = env::var("MICROBIN_WIDE").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_WIDE环境变量");
        String::new()
    });
    let _hash_ids = env::var("MICROBIN_HASH_IDS").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_HASH_IDS环境变量");
        String::new()
    });
    let _encryption_client_side = env::var("MICROBIN_ENCRYPTION_CLIENT_SIDE").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ENCRYPTION_CLIENT_SIDE环境变量");
        String::new()
    });
    let _encryption_server_side = env::var("MICROBIN_ENCRYPTION_SERVER_SIDE").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_ENCRYPTION_SERVER_SIDE环境变量");
        String::new()
    });
    let _max_file_size_encrypted = env::var("MICROBIN_MAX_FILE_SIZE_ENCRYPTED_MB").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_MAX_FILE_SIZE_ENCRYPTED_MB环境变量");
        String::new()
    });
    let _max_file_size_unencrypted = env::var("MICROBIN_MAX_FILE_SIZE_UNENCRYPTED_MB").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_MAX_FILE_SIZE_UNENCRYPTED_MB环境变量");
        String::new()
    });
    let _disable_update_checking = env::var("MICROBIN_DISABLE_UPDATE_CHECKING").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_DISABLE_UPDATE_CHECKING环境变量");
        String::new()
    });
    let _disable_telemetry = env::var("MICROBIN_DISABLE_TELEMETRY").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_DISABLE_TELEMETRY环境变量");
        String::new()
    });
    let _list_server = env::var("MICROBIN_LIST_SERVER").unwrap_or_else(|_| {
        println!("WARNING：未配置MICROBIN_LIST_SERVER环境变量");
        String::new()
    });

    Builder::new()
        .format(|buf, record| {
            writeln!(
                buf,
                "{} [{}] - {}",
                Local::now().format("%Y-%m-%dT%H:%M:%S"),
                record.level(),
                record.args()
            )
        })
        .filter(None, LevelFilter::Info)
        .init();

    log::info!(
        "MicroBin starting on http://{}:{}",
        ARGS.bind.to_string(),
        ARGS.port.to_string()
    );

    match fs::create_dir_all(format!("./{}/public", ARGS.data_dir)) {
        Ok(dir) => dir,
        Err(error) => {
            log::error!(
                "Couldn't create data directory ./{}/attachments/: {:?}",
                ARGS.data_dir,
                error
            );
            panic!(
                "Couldn't create data directory ./{}/attachments/: {:?}",
                ARGS.data_dir, error
            );
        }
    };

    let data = web::Data::new(AppState {
        pastas: Mutex::new(read_all()),
        sessions: Mutex::new(HashMap::new()),
    });

    if !ARGS.disable_telemetry {
        start_telemetry_thread();
    }

    let app_state_clone = data.clone();
    tokio::spawn(async move {
        let mut interval = time::interval(TokioDuration::from_secs(60 * 60));
        loop {
            interval.tick().await;
            let now = Utc::now();
            let mut sessions = app_state_clone.sessions.lock().unwrap();
            sessions.retain(|_, &mut expiry| expiry > now);
            log::info!("已清理过期的会话");
        }
    });

    HttpServer::new(move || {
        App::new()
            .app_data(data.clone())
            .wrap(middleware::NormalizePath::trim())
            .service(create::index)
            .service(guide::guide)
            .service(auth_admin::auth_admin)
            .service(auth_upload::auth_file_with_status)
            .service(auth_admin::auth_admin_with_status)
            .service(auth_upload::auth_upload_with_status)
            .service(auth_upload::auth_raw_pasta_with_status)
            .service(auth_upload::auth_edit_private_with_status)
            .service(auth_upload::auth_remove_private_with_status)
            .service(auth_upload::auth_file)
            .service(auth_upload::auth_upload)
            .service(auth_upload::auth_raw_pasta)
            .service(auth_upload::auth_edit_private)
            .service(auth_upload::auth_remove_private)
            .service(pasta_endpoint::getpasta)
            .service(pasta_endpoint::postpasta)
            .service(pasta_endpoint::getshortpasta)
            .service(pasta_endpoint::postshortpasta)
            .service(pasta_endpoint::getrawpasta)
            .service(pasta_endpoint::postrawpasta)
            .service(pasta_endpoint::redirecturl)
            .service(pasta_endpoint::shortredirecturl)
            .service(edit::get_edit)
            .service(edit::get_edit_with_status)
            .service(edit::post_edit)
            .service(edit::post_edit_private)
            .service(edit::post_submit_edit_private)
            .service(admin::get_admin)
            .service(admin::post_admin)
            .service(admin::logout)
            .service(static_resources::static_resources)
            .service(qr::getqr)
            .service(file::get_file)
            .service(file::post_secure_file)
            .service(web::resource("/upload").route(web::post().to(create::create)))
            .default_service(web::route().to(errors::not_found))
            .wrap(middleware::Logger::default())
            .service(remove::remove)
            .service(remove::post_remove)
            .service(list::list)
            .service(create::index_with_status)
            .wrap(Condition::new(
                ARGS.auth_basic_username.is_some()
                    && ARGS.auth_basic_username.as_ref().unwrap().trim() != "",
                HttpAuthentication::basic(util::auth::auth_validator),
            ))
    })
    .bind((ARGS.bind, ARGS.port))?
    .workers(ARGS.threads as usize)
    .run()
    .await
}
