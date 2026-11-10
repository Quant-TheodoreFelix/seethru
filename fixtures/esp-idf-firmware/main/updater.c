#include "updater.h"

#include "esp_ota_ops.h"

esp_err_t updater_write_image(httpd_req_t *req)
{
    char chunk[512];
    esp_ota_handle_t handle;
    const esp_partition_t *slot = esp_ota_get_next_update_partition(NULL);
    esp_err_t err = esp_ota_begin(slot, OTA_SIZE_UNKNOWN, &handle);
    if (err != ESP_OK) {
        return err;
    }
    int left = req->content_len;
    while (left > 0) {
        int got = httpd_req_recv(req, chunk, sizeof(chunk));
        if (got <= 0) {
            esp_ota_abort(handle);
            return ESP_FAIL;
        }
        esp_ota_write(handle, chunk, got);
        left -= got;
    }
    err = esp_ota_end(handle);
    if (err != ESP_OK) {
        return err;
    }
    return esp_ota_set_boot_partition(slot);
}
