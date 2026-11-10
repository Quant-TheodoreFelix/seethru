#pragma once

#include "esp_err.h"
#include "esp_http_server.h"

esp_err_t updater_write_image(httpd_req_t *req);
