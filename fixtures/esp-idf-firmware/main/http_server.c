#include <string.h>

#include "esp_http_server.h"
#include "updater.h"

static esp_err_t get_status(httpd_req_t *req)
{
    return httpd_resp_sendstr(req, "{\"ok\":true}");
}

static esp_err_t post_update(httpd_req_t *req)
{
    esp_err_t err = updater_write_image(req);
    if (err != ESP_OK) {
        return httpd_resp_send_500(req);
    }
    return httpd_resp_sendstr(req, "restarting");
}

static bool admin_password_matches(httpd_req_t *req)
{
    char given[64] = {0};
    if (httpd_req_get_hdr_value_str(req, "X-Admin-Password", given, sizeof(given)) != ESP_OK) {
        return false;
    }
    return strcmp(given, stored_admin_password()) == 0;
}

static esp_err_t post_admin_update(httpd_req_t *req)
{
    if (!admin_password_matches(req)) {
        return httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "no");
    }
    return updater_write_image(req);
}

void start_http_server(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    if (httpd_start(&server, &config) != ESP_OK) {
        return;
    }
    const httpd_uri_t routes[] = {
        { .uri = "/api/status", .method = HTTP_GET, .handler = get_status },
        { .uri = "/api/update", .method = HTTP_POST, .handler = post_update },
        { .uri = "/api/admin/update", .method = HTTP_POST, .handler = post_admin_update },
    };
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); i++) {
        httpd_register_uri_handler(server, &routes[i]);
    }
}
