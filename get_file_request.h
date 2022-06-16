#ifndef get_file_request_h
#define get_file_request_h 

#include "defines.h"

struct get_file_request {
	enum file_type {
		none, js, css, html, gif, ico, png
	};
	file_type 	type;
	char 		file_name[32];
	long 		length;
	bool 		gzip;
	const char *content_type;
	long 		size(){return length;};
	const char* name(){return file_name;};

	get_file_request(const char *uri){
		//DEBUG_PRINT("handle_send_file_request: "); DEBUG_PRINTLN(uri);
		int len = 0;
		#if !defined(ESP8266)
		file_name[len++] = 'd';
		file_name[len++] = 'a';
		file_name[len++] = 't';
		file_name[len++] = 'a';
        #endif
		
		const char *ext = NULL;
		while(true){
			if (!uri || *uri == '\0' || *uri == ' ' || len == sizeof(file_name)-1){
				file_name[len] = '\0';
				break;
			}
			if (*uri == '.')
				ext = uri + 1;
			file_name[len++] = *uri++;
		}

		if (ext == NULL) {type = file_type::none; content_type = ""; return;}
		set_file_type(ext);

		// check if compressed version of file is available
		int name_length = strlen(this->file_name);
		strcat(this->file_name, ".gz");
		this->length = file_length(this->file_name);
        DEBUG_PRINTF("File: name=%s, length=%u\n", this->file_name, this->length);
		gzip = length > 0;
		if (!gzip) {
			file_name[name_length] = 0;
			length = file_length(file_name);
            DEBUG_PRINTF("File: name=%s, length=%u\n", this->file_name, this->length);
		}
	}

    void set_file_type(const char *ext){
		if (memcmp(ext, "png", 3)==0) {type = file_type::png; content_type = "image/png\r\n"; return;}
		if (memcmp(ext, "ico", 3)==0) {type = file_type::ico; content_type = "image/vnd.microsoft.icon\r\n"; return;}
		if (memcmp(ext, "gif", 3)==0) {type = file_type::gif; content_type = "image/gif\r\n"; return;}
		if (memcmp(ext, "css", 3)==0) {type = file_type::css; content_type = "text/css\r\n"; return;}
		if (memcmp(ext, "htm", 3)==0) {type = file_type::css; content_type = "text/html\r\n"; return;}
		if (memcmp(ext, "js",  2)==0) {type = file_type::js;  content_type = "application/javascript\r\n"; return;}
    }

    void send_page_not_found(){
        print_json_header();
        bfill.emit_p(PSTR("\"result\":$D}"), HTML_PAGE_NOT_FOUND);
        send_packet(true);
    }

	bool send_file() {
        if (this->type == file_type::none)
            return false;

        DEBUG_PRINTF("Sending file: name=%s, length=%u\n", this->file_name, this->length);
		
		if (this->length < 0){
			send_page_not_found();
            return true;
		}

		// send header
		const char * content_encoding = this->gzip ? "content-encoding: gzip\r\n" : "";
		bfill.emit_p(PSTR("$FAccept-Ranges: bytes\r\nContent-Type: $F$F$F$FContent-Length: $D\r\n\r\n"), 
			html200OK, this->content_type, htmlCacheCtrl, htmlAccessControl, content_encoding, this->length);
		//DEBUG_PRINTLN(ether_buffer);
		send_packet(false);

	#if defined(ESP8266)
        File fp = SPIFFS.open(this->file_name, "r");
    #else
        FILE *fp = fopen(this->file_name, "rb");
    #endif
		if(fp) {
			while(1) {
                #if defined(ESP8266)
				size_t len = fp.read((uint8_t*)ether_buffer, ETHER_BUFFER_SIZE);
                #else
                size_t len = fread(ether_buffer, 1, ETHER_BUFFER_SIZE, fp);
                #endif
				if (len == 0 || len == EOF)
					break;
				if (m_client)
					m_client->write((const uint8_t*)ether_buffer, len);
#if defined(ARDUINO)
				else
					wifi_server->client().write(ether_buffer, len);
#endif
			}
            #if defined(ESP8266)
            fp.close();
			#else
            fclose(fp);
            #endif
			DEBUG_PRINTF("File %s (%u) sent\n", this->file_name, this->length);
		} else {
			DEBUG_PRINTF("Failed to open file: %s\n", this->file_name);
		}

        if (m_client)
            m_client->stop();
#if defined(ARDUINO)			
        else if (wifi_server->client())
            wifi_server->client().stop();
#endif
        return true;
	}
};
#endif
