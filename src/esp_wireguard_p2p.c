/*
 * Copyright (c) 2023 Tobias Schramm <t.schramm@t-sys.eu>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *  list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 *  list of conditions and the following disclaimer in the documentation and/or
 *  other materials provided with the distribution.
 *
 * 3. Neither the name of "Floorsense Ltd", "Agile Workspace Ltd" nor the names of
 *  its contributors may be used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
 * ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <string.h>

#include <esp_log.h>

#include "esp_wireguard.h"
#include "wireguardif.h"

static const char *TAG = "esp_wireguard_p2p";

esp_err_t esp_wireguard_p2p_init(const esp_wireguard_p2p_config_t *config, esp_wireguard_p2p_t *wg) {
	memset(wg, 0, sizeof(*wg));
	return esp_wireguard_init(&config->local, &wg->wg);
}

esp_err_t esp_wireguard_p2p_connect(const esp_wireguard_p2p_config_t *config, esp_wireguard_p2p_t *wg) {
	esp_err_t err = esp_wireguard_add_peer(&config->peer, &wg->wg, &wg->peer_index);
	if (err) {
		ESP_LOGE(TAG, "Failed to add peer");
		return err;
	}
	wg->peer_added = true;
	err = esp_wireguard_connect_peer(&wg->wg, wg->peer_index);
	if (err) {
		if (!esp_wireguard_remove_peer(&wg->wg, wg->peer_index)) {
			wg->peer_added = false;
		}
	}
	wg->peer_connected = true;
	return err;
}

esp_err_t esp_wireguard_p2p_set_default(esp_wireguard_p2p_t *wg) {
	return esp_wireguard_set_default(&wg->wg);
}

esp_err_t esp_wireguard_p2p_is_up(esp_wireguard_p2p_t *wg) {
	if (!wg->peer_connected) {
		return false;
	}

	return esp_wireguard_peer_is_up(&wg->wg, wg->peer_index);
}

esp_err_t esp_wireguard_p2p_disconnect(esp_wireguard_p2p_t *wg) {
	esp_err_t err;
	if (wg->peer_connected) {
		err = esp_wireguard_disconnect_peer(&wg->wg, wg->peer_index);
		if (err) {
			return err;
		}
		wg->peer_connected = false;
	}

	if (wg->peer_added) {
		err = esp_wireguard_remove_peer(&wg->wg, wg->peer_index);
		if (err) {
			return err;
		}
		wg->peer_added = false;
	}

    if (wg->wg.netif_default) {
		wireguardif_unbind_underlying_weak(&wg->wg.netif);
        netif_set_default(wg->wg.netif_default);
		wg->wg.netif_default = NULL;
    }
	return ESP_OK;
}

esp_err_t esp_wireguard_p2p_free(esp_wireguard_p2p_t *wg) {
	esp_err_t err = esp_wireguard_p2p_disconnect(wg);
	if (err) {
		return err;
	}
    wireguardif_shutdown(&wg->wg.netif);
    netif_remove(&wg->wg.netif);
	return ESP_OK;
}
