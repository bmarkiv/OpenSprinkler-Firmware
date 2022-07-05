/* OpenSprinkler Unified (AVR/RPI/BBB/LINUX) Firmware
 * Copyright (C) 2015 by Ray Wang (ray@opensprinkler.com)
 *
 * Server functions
 * Feb 2015 @ OpenSprinkler.com
 *
 * This file is part of the OpenSprinkler library
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see
 * <http://www.gnu.org/licenses/>. 
 */
 
#ifndef _OPENSPRINKLER_SERVER_H
#define _OPENSPRINKLER_SERVER_H

#if !defined(ARDUINO)
#include <stdarg.h>
#endif

char dec2hexchar(byte dec);

class BufferFiller {
	char *start; //!< Pointer to start of buffer
	char *ptr; //!< Pointer to cursor position
	int  size;
public:
	BufferFiller () {}
	void init(char *buf, int buf_size) {
		start  = buf;
		ptr    = buf;
		buf[0] = 0;
		size   = buf_size;
	}

	void emit_p(PGM_P fmt, ...) {
		va_list ap;
		va_start(ap, fmt);
		char tmp_buf[MAX_SOPTS_SIZE+1];

		for (;;) {
			char c = pgm_read_byte(fmt++);
			if (c == 0)
				break;
			if (c != '$') {
				add(c);
				continue;
			}
			c = pgm_read_byte(fmt++);
			switch (c) {
			case 'D':
				//wtoa(va_arg(ap, uint16_t), (char*) ptr);
				itoa(va_arg(ap, int), tmp_buf, 10);  // ray
				add(tmp_buf);
				break;
			case 'L':
				//ltoa(va_arg(ap, long), (char*) ptr, 10);
				ultoa(va_arg(ap, long), tmp_buf, 10); // ray
				add(tmp_buf);
				break;
			case 'S':
				add(va_arg(ap, const char*));
				break;
			case 'X': {
				char d = va_arg(ap, int);
				add(dec2hexchar((d >> 4) & 0x0F));
				add(dec2hexchar(d & 0x0F));
				size -= 2;
			}
				continue;
			case 'F': {
				PGM_P s = va_arg(ap, PGM_P);
				char d;
				while ((d = pgm_read_byte(s++)) != 0)
					add(d);
				continue;
			}
			case 'O': {
				uint16_t oid = va_arg(ap, int);
				file_read_block(SOPTS_FILENAME, tmp_buf, oid*MAX_SOPTS_SIZE, MAX_SOPTS_SIZE);
				tmp_buf[MAX_SOPTS_SIZE] = 0;
				add(tmp_buf);
			}
				break;
			default:
				add(c);
				continue;
			}
		}
		*(ptr)=0;
		va_end(ap);
	}

	char* buffer () const { return start; }
	unsigned int position () const { return ptr - start; }

private:
	void add(char c) {
		if (size - position() == 1){
			this->send(start, position());
		}
		*ptr++ = c;
	}
	void add(const char * tmp_buf) {
		int tmp_buf_length = strlen(tmp_buf);
		if (tmp_buf_length > size - position() - 1){
			this->send(start, position());
			this->send(tmp_buf, tmp_buf_length);
			return;
		}
			
		memcpy(ptr, tmp_buf, tmp_buf_length);
		ptr += tmp_buf_length;
	}

	void send(const char *packet, int packet_size) {
			void send_packet(const char *packet, int packet_size);
			send_packet(packet, packet_size);
			ptr = start;
			*(ptr)=0;
		}

};


#endif // _OPENSPRINKLER_SERVER_H