// light_option.c
// Created on: Nov 1, 2016

// Copyright (c) 2016 Radu Velea

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

#include <stdlib.h>
#include "light_pcapng.h"

#include "light_debug.h"
#include "light_internal.h"

uint16_t *light_get_num_options(const light_pcapng pcapng, uint16_t *num_options)
{
	if (pcapng == NULL) {
		return 0;
	}

	int local_num_options = 0;
	uint16_t *option_codes = NULL;

	light_option iterator = pcapng->options;

	// We don't care about comments
	while (iterator != NULL) {
		if (iterator->custom_option_code > 1)
			 local_num_options++;
		iterator = iterator->next_option;
	}

	if (local_num_options > 0) {
		int option_index = 0;
		option_codes = (uint16_t *)calloc(local_num_options, sizeof(uint16_t));
	        iterator = pcapng->options;

	        while (iterator != NULL) {
			if (iterator->custom_option_code > 0) {
				option_codes[option_index] = iterator->custom_option_code;
				option_index++;
			}
			iterator = iterator->next_option;
		}
	}
	else
		option_codes = NULL;

	*num_options = local_num_options;

	return option_codes;
}


light_option light_get_option(const light_pcapng pcapng, uint16_t option_code)
{
	if (pcapng == NULL) {
		return NULL;
	}

	light_option iterator = pcapng->options;

	while (iterator != NULL) {
		if (iterator->custom_option_code == option_code) {
			break;
		}
		iterator = iterator->next_option;
	}

	return iterator;
}

uint16_t light_get_option_code(const light_option option)
{
	return option->custom_option_code;
}

const light_option light_get_next_option(const light_option option)
{
	return option->next_option;
}

uint32_t *light_get_option_data(const light_option option)
{
	return option->data;
}

uint16_t light_get_option_length(const light_option option)
{
	return option->option_length;
}

