/*
 * Copyright (c) 2022 Tomoyuki Sakurai <y@trombik.org>
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

#include <assert.h>
#include <string.h>
#include <inttypes.h>
#include <lwip/ip.h>
#include <lwip/netdb.h>
#include <lwip/err.h>
#include <esp_err.h>
#include <esp_log.h>
#include <esp_wireguard.h>
#include <mbedtls/base64.h>

#include "wireguard-platform.h"
#include "wireguardif.h"

#define TAG "esp_wireguard"
#define WG_KEY_LEN  (32)
#define WG_B64_KEY_LEN (4 * ((WG_KEY_LEN + 2) / 3))
#if defined(CONFIG_LWIP_IPV6)
#define WG_ADDRSTRLEN  INET6_ADDRSTRLEN
#else
#define WG_ADDRSTRLEN  INET_ADDRSTRLEN
#endif

static bool esp_wireguard_platform_init_done = false;
static unsigned int esp_wireguard_if_cnt = 0;

static esp_err_t esp_wireguard_peer_init(const esp_wireguard_peer_config_t *config, struct wireguardif_peer *peer, uint8_t *psk_buffer) {
    esp_err_t err;
    char addr_str[WG_ADDRSTRLEN];
    struct addrinfo *res = NULL;
    struct addrinfo hints;
    ip_addr_t allowed_ip = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    ip_addr_t allowed_ip_mask = IPADDR4_INIT_BYTES(0, 0, 0, 0);

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;

    if (!config || !peer) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    peer->public_key = config->public_key;
    if (config->preshared_key != NULL) {
        size_t len;
        int res;

        ESP_LOGI(TAG, "using preshared_key");
        ESP_LOGD(TAG, "preshared_key: %s", config->preshared_key);
#if defined(CONFIG_WIREGUARD_x25519_IMPLEMENTATION_DEFAULT)
        ESP_LOGI(TAG, "X25519: default");
#elif defined(CONFIG_WIREGUARD_x25519_IMPLEMENTATION_NACL)
        ESP_LOGI(TAG, "X25519: NaCL");
#endif
        res = mbedtls_base64_decode(psk_buffer, WG_KEY_LEN, &len, (unsigned char *)config->preshared_key, WG_B64_KEY_LEN);
        if (res != 0 || len != WG_KEY_LEN) {
            err = ESP_FAIL;
            ESP_LOGE(TAG, "base64_decode: %i", res);
            if (len != WG_KEY_LEN) {
                ESP_LOGE(TAG, "invalid decoded length, len: %u, should be %u", len, WG_KEY_LEN);
            }
            goto fail;
        }
        peer->preshared_key = psk_buffer;
    } else {
        peer->preshared_key = NULL;
    }
    peer->keep_alive = config->persistent_keepalive;

	if (config->allowed_ip) {
	    if (ipaddr_aton(config->allowed_ip, &allowed_ip) != 1) {
	        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip: `%s`", config->allowed_ip);
	        err = ESP_ERR_INVALID_ARG;
	        goto fail;
	    }
	}
    peer->allowed_ip = allowed_ip;
	if (config->allowed_ip_mask) {
	    if (ipaddr_aton(config->allowed_ip_mask, &allowed_ip_mask) != 1) {
	        ESP_LOGE(TAG, "ipaddr_aton: invalid allowed_ip_mask: `%s`", config->allowed_ip_mask);
	        err = ESP_ERR_INVALID_ARG;
	        goto fail;
	    }
	}
    peer->allowed_mask = allowed_ip_mask;

    /* resolve peer name or IP address */
    {
        ip_addr_t endpoint_ip;
        memset(&endpoint_ip, 0, sizeof(endpoint_ip));

        /* XXX lwip_getaddrinfo returns only the first address of a host at the moment */
        if (getaddrinfo(config->endpoint, NULL, &hints, &res) != 0) {
            err = ESP_FAIL;

            /* XXX gai_strerror() is not implemented */
            ESP_LOGE(TAG, "getaddrinfo: unable to resolve `%s`", config->endpoint);
            goto fail;
        }

        if (res->ai_family == AF_INET) {
            struct in_addr addr4 = ((struct sockaddr_in *) (res->ai_addr))->sin_addr;
            inet_addr_to_ip4addr(ip_2_ip4(&endpoint_ip), &addr4);
        } else {
#if defined(CONFIG_LWIP_IPV6)
            struct in6_addr addr6 = ((struct sockaddr_in6 *) (res->ai_addr))->sin6_addr;
            inet6_addr_to_ip6addr(ip_2_ip6(&endpoint_ip), &addr6);
#endif
        }
        peer->endpoint_ip = endpoint_ip;

        if (inet_ntop(res->ai_family, &(peer->endpoint_ip), addr_str, WG_ADDRSTRLEN) == NULL) {
            ESP_LOGW(TAG, "inet_ntop: %i", errno);
        } else {
            ESP_LOGI(TAG, "Peer: %s (%s:%i)",
                                            config->endpoint,
                                            addr_str,
                                            config->port);
        }
    }
    peer->endport_port = config->port;
    peer->keep_alive = config->persistent_keepalive;
    err = ESP_OK;
fail:
    freeaddrinfo(res);
    return err;
}

static esp_err_t esp_wireguard_netif_create(const esp_wireguard_config_t *config, esp_wireguard_t *wg) {
    esp_err_t err;
    ip_addr_t ip_addr;
    ip_addr_t netmask;
    ip_addr_t gateway = IPADDR4_INIT_BYTES(0, 0, 0, 0);
    struct wireguardif_init_data ifinit = {0};
	struct netif *wg_netif;

    if (!config) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    /* Setup the WireGuard device structure */
	ifinit.interface_num = esp_wireguard_if_cnt;
    ifinit.private_key = config->private_key;
    ifinit.listen_port = config->listen_port;
    ifinit.bind_netif = NULL;
    if (config->bind_netif != NULL) {
        struct netif* bind_if = netif_find(config->bind_netif);
        if (bind_if == NULL) {
            ESP_LOGE(TAG, "Unknown bind interface `%s`", config->bind_netif);
            err = ESP_ERR_INVALID_ARG;
            goto fail;
        }
        ifinit.bind_netif = bind_if;
    }

    ESP_LOGI(TAG, "local_ip: %s", config->local_ip);

    if (ipaddr_aton(config->local_ip, &ip_addr) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid local_ip: `%s`", config->local_ip);
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }
    if (ipaddr_aton(config->local_ip_mask, &netmask) != 1) {
        ESP_LOGE(TAG, "ipaddr_aton: invalid local_ip_mask: `%s`", config->local_ip_mask);
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }
	if (config->gateway_ip) {
	    if (ipaddr_aton(config->gateway_ip, &gateway) != 1) {
	        ESP_LOGE(TAG, "ipaddr_aton: invalid gateway_ip: `%s`", config->gateway_ip);
	        err = ESP_ERR_INVALID_ARG;
	        goto fail;
	    }
	}

    /* Register the new WireGuard network interface with lwIP */
    wg_netif = netif_add(
            &wg->netif,
            ip_2_ip4(&ip_addr),
            ip_2_ip4(&netmask),
            ip_2_ip4(&gateway),
            &ifinit, &wireguardif_init,
            &ip_input);
    if (wg_netif == NULL) {
        ESP_LOGE(TAG, "netif_add: failed");
        err = ESP_FAIL;
        goto fail;
    }

    /* Mark the interface as administratively up, link up flag is set
     * automatically when peer connects */
    netif_set_up(wg_netif);
    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_init(const esp_wireguard_config_t *config, esp_wireguard_t *wg) {
	if (!esp_wireguard_platform_init_done) {
	    esp_err_t err = wireguard_platform_init();
	    if (err) {
	        ESP_LOGE(TAG, "wireguard_platform_init: %s", esp_err_to_name(err));
			return err;
	    }
		esp_wireguard_platform_init_done = true;
	}

	memset(wg, 0, sizeof(*wg));
	esp_err_t err = esp_wireguard_netif_create(config, wg);
	if (err) {
		ESP_LOGE(TAG, "esp_wireguard_netif_create: %s", esp_err_to_name(err));
		return err;
	}
	esp_wireguard_if_cnt++;

    return err;
}

esp_err_t esp_wireguard_add_peer(const esp_wireguard_peer_config_t *config, esp_wireguard_t *wg, uint8_t *out_peer_index) {
    esp_err_t err = ESP_FAIL;
    err_t lwip_err = -1;
	uint8_t psk[WG_KEY_LEN];
	struct wireguardif_peer peer;

    if (!wg) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

	err = esp_wireguard_peer_init(config, &peer, psk);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wireguard_peer_init: %s", esp_err_to_name(err));
        goto fail;
    }

    /* Register the new WireGuard peer with the network interface */
	uint8_t peer_idx;
    lwip_err = wireguardif_add_peer(&wg->netif, &peer, &peer_idx);
    if (lwip_err != ERR_OK || peer_idx == WIREGUARDIF_INVALID_INDEX) {
        ESP_LOGE(TAG, "wireguardif_add_peer: %i", lwip_err);
        goto fail;
    }
    if (ip_addr_isany(&peer.endpoint_ip)) {
        err = ESP_FAIL;
        goto fail;
    }
	if (out_peer_index) {
		*out_peer_index = peer_idx;
	}

    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_connect_peer(esp_wireguard_t *wg, uint8_t peer_index) {
    err_t lwip_err = wireguardif_connect(&wg->netif, peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGE(TAG, "wireguardif_connect: %i", lwip_err);
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t esp_wireguard_set_default(esp_wireguard_t *wg) {
    esp_err_t err;
    if (!wg) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }
    wg->netif_default = netif_default;
	wireguardif_bind_underlying_weak(&wg->netif, wg->netif_default);
    netif_set_default(&wg->netif);
    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_disconnect_peer(esp_wireguard_t *wg, uint8_t peer_index) {
    esp_err_t err;
    err_t lwip_err;

    if (!wg) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    lwip_err = wireguardif_disconnect(&wg->netif, peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_disconnect: peer_index: %" PRIu8 " err: %i", peer_index, lwip_err);
    }

    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_remove_peer(esp_wireguard_t *wg, uint8_t peer_index) {
    esp_err_t err;
    err_t lwip_err;

    if (!wg) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    lwip_err = wireguardif_remove_peer(&wg->netif, peer_index);
    if (lwip_err != ERR_OK) {
        ESP_LOGW(TAG, "wireguardif_remove_peer: peer_index: %" PRIu8 " err: %i", peer_index, lwip_err);
    }

    err = ESP_OK;
fail:
    return err;
}

esp_err_t esp_wireguard_disconnect(esp_wireguard_t *wg) {
    esp_err_t err;

    if (!wg) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    if (wg->netif_default) {
		wireguardif_unbind_underlying_weak(&wg->netif);
        netif_set_default(wg->netif_default);
		wg->netif_default = NULL;
    }
    wireguardif_shutdown(&wg->netif);
    netif_remove(&wg->netif);
    err = ESP_OK;
fail:
    return err;

}

esp_err_t esp_wireguard_peer_is_up(esp_wireguard_t *wg, uint8_t peer_index) {
    esp_err_t err;
    err_t lwip_err;

    if (!wg) {
        err = ESP_ERR_INVALID_ARG;
        goto fail;
    }

    lwip_err = wireguardif_peer_is_up(
            &wg->netif,
            peer_index,
			NULL,
			NULL);

    if (lwip_err != ERR_OK) {
        err = ESP_FAIL;
        goto fail;
    }
    err = ESP_OK;
fail:
    return err;
}
