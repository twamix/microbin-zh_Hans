use crate::args::{Args, ARGS};
use crate::pasta::Pasta;
use crate::util::version::{Version, CURRENT_VERSION};
use crate::AppState;
use actix_multipart::Multipart;
use actix_web::{get, post, web, Error, HttpResponse, HttpRequest, cookie::Cookie};
use askama::Template;
use futures::TryStreamExt;
use uuid::Uuid;
use chrono::{Duration, Utc};
use time::OffsetDateTime;

#[derive(Template)]
#[template(path = "admin.html")]
struct AdminTemplate<'a> {
    pastas: &'a Vec<Pasta>,
    args: &'a Args,
    status: &'a String,
    version_string: &'a String,
    message: &'a String,
    update: &'a Option<Version>,
}

#[get("/admin")]
pub async fn get_admin(req: HttpRequest, data: web::Data<AppState>) -> Result<HttpResponse, Error> {
    if let Some(cookie) = req.cookie("admin_session") {
        let session_token = cookie.value().to_string();
        let mut sessions = data.sessions.lock().unwrap();

        if let Some(&expiration_time) = sessions.get(&session_token) {
            if Utc::now() < expiration_time {
                let pastas = data.pastas.lock().unwrap();
                let mut status = "良好".to_string();
                let mut message = "Microbin 正常运行中！".to_string();

                if ARGS.public_path.is_none() {
                    status = "警告".to_string();
                    message = "未配置 public_path 参数设置站点链接。二维码分享和复制功能已被禁用！".to_string();
                }

                if ARGS.auth_admin_username == "admin" && ARGS.auth_admin_password == "m1cr0b1n" {
                    status = "危险".to_string();
                    message = "您正在使用默认管理员账号密码登录后台！这存在安全风险，请尽快更改！".to_string();
                }

                return Ok(HttpResponse::Ok().content_type("text/html").body(
                    AdminTemplate {
                        pastas: &pastas,
                        args: &ARGS,
                        status: &status,
                        version_string: &format!("{}", CURRENT_VERSION.long_title),
                        message: &message,
                        update: &None,
                    }
                    .render()
                    .unwrap(),
                ));
            } else {
                sessions.remove(&session_token);
            }
        }
    }
    Ok(HttpResponse::Found()
        .append_header(("Location", "/auth_admin"))
        .finish())
}

#[post("/admin")]
pub async fn post_admin(
    _req: HttpRequest,
    data: web::Data<AppState>,
    mut payload: Multipart,
) -> Result<HttpResponse, Error> {
    let mut username = String::new();
    let mut password = String::new();

    while let Some(mut field) = payload.try_next().await? {
        if field.name() == "username" {
            while let Some(chunk) = field.try_next().await? {
                username.push_str(std::str::from_utf8(&chunk).unwrap());
            }
        } else if field.name() == "password" {
            while let Some(chunk) = field.try_next().await? {
                password.push_str(std::str::from_utf8(&chunk).unwrap());
            }
        }
    }

    if username != ARGS.auth_admin_username || password != ARGS.auth_admin_password {
        return Ok(HttpResponse::Found()
            .append_header(("Location", "/auth_admin/incorrect"))
            .finish());
    }

    let session_token = Uuid::new_v4().to_string();
    let expiration_time = Utc::now() + Duration::days(1);

    {
        let mut sessions = data.sessions.lock().unwrap();
        sessions.insert(session_token.clone(), expiration_time);
    }

    let offset_expiration = OffsetDateTime::from_unix_timestamp(expiration_time.timestamp()).unwrap();

    let cookie = Cookie::build("admin_session", session_token)
        .path("/admin")
        .http_only(true)
        .expires(offset_expiration)
        .finish();

    Ok(HttpResponse::Found()
        .append_header(("Location", "/admin"))
        .cookie(cookie)
        .finish())
}

#[get("/logout")]
pub async fn logout(data: web::Data<AppState>, req: HttpRequest) -> Result<HttpResponse, Error> {
    if let Some(cookie) = req.cookie("admin_session") {
        let session_token = cookie.value().to_string();
        let mut sessions = data.sessions.lock().unwrap();
        sessions.remove(&session_token);
    }

    let past_expiration = (Utc::now() - Duration::days(1)).timestamp();
    let offset_past_expiration = OffsetDateTime::from_unix_timestamp(past_expiration).unwrap();

    let remove_cookie = Cookie::build("admin_session", "")
        .path("/admin")
        .http_only(true)
        .expires(offset_past_expiration)
        .finish();

    Ok(HttpResponse::Found()
        .append_header(("Location", "/auth_admin"))
        .cookie(remove_cookie)
        .finish())
}