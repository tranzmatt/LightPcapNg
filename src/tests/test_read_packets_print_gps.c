// test_read_packets.c
// Created on: Nov 14, 2016

// Copyright (c) 2016

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.

#include "light_pcapng_ext.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#define CUSTOM_BYTES_SAFE 2989

typedef struct __attribute__((packed)) kismet_gps_v1_fixed_t {
    uint32_t pen;
    uint8_t magic_number;
    uint8_t version;
    uint16_t length;
    uint32_t mask;
    uint32_t longitude;
    uint32_t latitude;
    uint32_t altitude;
} kismet_gps_v1_fixed;

typedef struct __attribute__((packed)) kismet_gps_v1_t {
    uint32_t pen;
    uint8_t magic_number;
    uint8_t version;
    uint16_t length;
    uint32_t mask;
    float longitude;
    float latitude;
    float altitude;
} kismet_gps_v1;



uint32_t float_to_fixed3_7(double flt) {
    if ((flt <= -180.0000001) || (flt >= +180.0000001)) {
	fprintf(stderr, "%f is an invalid value", flt);
	exit(-1);
    }

    int32_t scaled = (int32_t) ((flt) * (double) 10000000);
    return (u_int32_t) (scaled + ((int32_t) 180 * 10000000));
}

double fixed3_7_to_float(uint32_t fixed) {
    if (fixed > 3600000000) {
	fprintf(stderr, "%d is an invalid value", fixed);
	exit(-1);
    }

    int32_t remapped = fixed - (180 * 10000000);
    return (double) ((double) remapped / 10000000);
}


uint32_t float_to_fixed6_4(double flt) {
    if ((flt <= -180.0000001) || (flt >= +180.0000001)) {
	fprintf(stderr, "%f is an invalid value", flt);
	exit(-1);
    }

    int32_t scaled_l = (int32_t) ((flt) * (double) 10000);
    return (u_int32_t) (scaled_l + ((int32_t) 180000 * 10000));
}

double fixed6_4_to_float(uint32_t fixed) {
    if (fixed > 3600000000) {
	fprintf(stderr, "%d is an invalid value", fixed);
	exit(-1);
    }

    int32_t remapped = fixed - (180000 * 10000);
    return (double) ((double) remapped / 10000);
}


int extract_kismet_gps_v1_data(uint8_t *payload, kismet_gps_v1 *the_gps) {
    kismet_gps_v1_fixed* fixed_gps = (kismet_gps_v1_fixed *)payload;

    // check for kismet gps v1 tag
    if ((fixed_gps->pen == 55922) && (fixed_gps->magic_number == 0x47) && (fixed_gps->version == 0x1 )) {
	memcpy(the_gps, fixed_gps, sizeof(kismet_gps_v1));
	the_gps->longitude = fixed3_7_to_float(fixed_gps->longitude);
	the_gps->latitude = fixed3_7_to_float(fixed_gps->latitude);
	the_gps->altitude = fixed6_4_to_float(fixed_gps->altitude);
	return 1;
    }
    return 0;
}


int main(int argc, const char **args) {
	int i;

	for (i = 1; i < argc; ++i) {
		const char *file = args[i];
		light_pcapng_t *pcapng = light_pcapng_open_read(file, LIGHT_FALSE);
		if (pcapng != NULL) {
			light_pcapng_file_info *info = light_pcang_get_file_info(pcapng);
			printf("file version is %d.%d\n", info->major_version, info->minor_version);
			if (info->file_comment != NULL)
				printf("file comment is: %s\n", info->file_comment);
			if (info->os_desc != NULL)
				printf("os is: %s\n", info->os_desc);
			if (info->hardware_desc != NULL)
				printf("hardware description is: %s\n", info->hardware_desc);
			if (info->user_app_desc != NULL)
				printf("user app is: %s\n", info->user_app_desc);

			int index = 1;

			while (1) {
				light_packet_header pkt_header;
				const uint8_t *pkt_data = NULL;
				int res = 0;

				res = light_get_next_packet(pcapng, &pkt_header, &pkt_data);
				if (!res)
					break;

				if (pkt_data != NULL) {
					printf("packet #%d: orig_len=%d, cap_len=%d, iface_id=%d, data_link=%d, timestamp=%d.%06d",
							index,
							pkt_header.original_length,
							pkt_header.captured_length,
							pkt_header.interface_id,
							pkt_header.data_link,
							(int)pkt_header.timestamp.tv_sec,
							(int)pkt_header.timestamp.tv_usec);
					if (pkt_header.comment_length > 0) {
						printf(", comment=\"%s\"\n", pkt_header.comment);
					}
					else {
						printf("\n");
					}

					
					int num_options = pkt_header.num_custom_fields;

					if (num_options > 0) {
						for (int option = 0; option < num_options; option++) {
							if (pkt_header.custom_field_length[option] > 0) {
								if (((int)pkt_header.custom_field_type[option] == CUSTOM_BYTES_SAFE ) && (pkt_header.custom_field_length[option] == sizeof(kismet_gps_v1))) {
									kismet_gps_v1 my_gps = {0};
									printf("possible kismet gps v1 %d len %d = ", pkt_header.custom_field_type[option],
										pkt_header.custom_field_length[option]);
									extract_kismet_gps_v1_data((uint8_t*)pkt_header.custom_field_payload[option], &my_gps);
									printf("Lat %f, Lon %f, Alt %f\n", my_gps.latitude, my_gps.longitude, my_gps.altitude);
								}
								else
								{
									printf("generic custom  type %d len %d = ", pkt_header.custom_field_type[option],
										pkt_header.custom_field_length[option]);
									for (int i=0 ; i < pkt_header.custom_field_length[option]; i++)
									{
										printf("%02x ", (uint8_t)pkt_header.custom_field_payload[option][i]);
									}
								}
								printf("\n");
							}
							else {
								printf("\n");
							}
						}
					}

					index++;
				}
			}

			printf("interface count in file: %lu\n", info->interface_block_count);

			light_pcapng_close(pcapng);
		}
		else {
			fprintf(stderr, "Unable to read pcapng: %s\n", file);
		}
	}

	return 0;
}
