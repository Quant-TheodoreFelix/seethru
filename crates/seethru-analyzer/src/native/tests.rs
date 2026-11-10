use super::{collect, is_test_config, options};

const SERVER: &str = r#"
#include "esp_http_server.h"
#define TAG "http"

static bool helper(int x) { return x > 0; }

static esp_err_t write_image(httpd_req_t *req)
{
    char buf[64];
    if (helper(1)) {
        esp_ota_write(handle, buf, sizeof(buf));
    }
    return ESP_OK;
}

static esp_err_t POST_update(httpd_req_t *req) {
    ESP_LOGI(TAG, "update");
    return write_image(req);
}

static esp_err_t POST_login(httpd_req_t *req) {
    char value[32];
    httpd_req_get_hdr_value_str(req, "Authorization", value, sizeof(value));
    return ESP_OK;
}

class Device {
  public:
    void restart() const { esp_restart(); }
};

void start(void)
{
    const httpd_uri_t routes[] = {
        { .uri = "/api/update", .method = HTTP_POST, .handler = POST_update },
        { .uri = "/api/login", .method = HTTP_POST, .handler = POST_login, .user_ctx = NULL },
        { "/positional", HTTP_GET, POST_login, NULL },
    };
    httpd_uri_t single = {
        .uri = "/single",
        .method = HTTP_ANY,
        .handler = POST_login,
    };
    for (int i = 0; i < 2; i++) {
        httpd_uri_t entry = routes[i];
        entry.handler = wrap_all;
        httpd_register_uri_handler(server, &entry);
    }
}
"#;

#[test]
fn functions_calls_routes_and_wrappers_are_collected() {
    let facts = collect("main/server.c", SERVER);
    let names: Vec<&str> = facts.functions.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        names,
        [
            "helper",
            "write_image",
            "POST_update",
            "POST_login",
            "restart",
            "start"
        ]
    );
    let image = &facts.functions[1];
    let calls: Vec<&str> = image.calls.iter().map(|c| c.name.as_str()).collect();
    assert_eq!(calls, ["helper", "esp_ota_write"]);
    assert_eq!(image.calls[1].location.line, 11);
    assert!(!image.checks_caller);
    assert!(!facts.functions[2].checks_caller);
    assert!(facts.functions[3].checks_caller);

    let routes: Vec<(&str, Option<&str>, &str)> = facts
        .routes
        .iter()
        .map(|r| (r.uri.as_str(), r.method.as_deref(), r.handler.as_str()))
        .collect();
    assert_eq!(
        routes,
        [
            ("/api/update", Some("POST"), "POST_update"),
            ("/api/login", Some("POST"), "POST_login"),
            ("/single", None, "POST_login"),
        ]
    );
    assert_eq!(facts.wrappers, ["wrap_all"]);
    assert!(!facts.partial);
}

#[test]
fn option_files_are_read_line_by_line() {
    let found = options(
        "# CONFIG_SECURE_BOOT is not set\nCONFIG_ESP_HTTPS_OTA_ALLOW_HTTP=y\n  CONFIG_NAME=\"a b\"\nOTHER=1\nCONFIG_BAD KEY=y\n",
    );
    let pairs: Vec<(&str, &str)> = found
        .iter()
        .map(|line| (line.key.as_str(), line.value.as_str()))
        .collect();
    assert_eq!(
        pairs,
        [
            ("CONFIG_ESP_HTTPS_OTA_ALLOW_HTTP", "y"),
            ("CONFIG_NAME", "a b")
        ]
    );
    assert_eq!(found[1].offset, 68);
    assert!(is_test_config("sdkconfig.ci"));
    assert!(is_test_config("examples/a/sdkconfig.defaults"));
    assert!(!is_test_config("sdkconfig.defaults.esp32s3"));
}
