#include "nvs_flash.h"

void start_http_server(void);

void app_main(void)
{
    nvs_flash_init();
    start_http_server();
}
