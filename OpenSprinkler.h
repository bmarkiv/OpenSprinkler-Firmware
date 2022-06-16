/* OpenSprinkler Unified (AVR/RPI/BBB/LINUX/ESP8266) Firmware
 * Copyright (C) 2015 by Ray Wang (ray@opensprinkler.com)
 *
 * OpenSprinkler library header file
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


#ifndef _OPENSPRINKLER_H
#define _OPENSPRINKLER_H

#include "defines.h"
#include "utils.h"
#include "gpio.h"
#include "images.h"
#include "mqtt.h"
#include "StationAttributes.h"

#if defined(ARDUINO) // headers for ESP8266
	#include <Arduino.h>
	#include <Wire.h>
	#include <SPI.h>
	#include <Ethernet.h>
	#include "I2CRTC.h"

	#if defined(ESP8266)
		#include <FS.h>
		#include <RCSwitch.h>
		#include "SSD1306Display.h"
		#include "espconnect.h"
	#else
		#include <SdFat.h>
		#include "LiquidCrystal.h"
	#endif
	
#else // headers for RPI/BBB/LINUX
	#include <time.h>
	#include <string.h>
	#include <unistd.h>
	#include <netdb.h>	
	#include <sys/stat.h>  
	#include "etherport.h"
#endif // end of headers

extern const char iopt_json_names[];
extern const uint8_t iopt_max[];

class OpenSprinkler {
public:

	// data members
#if defined(ESP8266)
	static SSD1306Display lcd;	// 128x64 OLED display
#elif defined(ARDUINO)
	static LiquidCrystal lcd; // 16x2 character LCD
#else
	// todo: LCD define for RPI/BBB
#endif

#if defined(OSPI)
	static byte pin_sr_data;		// RPi shift register data pin
															// to handle RPi rev. 1
#endif

	static OSMqtt mqtt;

	static NVConData nvdata;
	static ConStatus status;
	static ConStatus old_status;
	static byte nstations;
	static byte hw_type;	// hardware type
	static byte hw_rev;		// hardware minor

	static byte iopts[]; // integer options
	static const char*sopts[]; // string options
	static byte station_bits[];			// station activation bits. each byte corresponds to a board (8 stations)
																	// first byte-> master controller, second byte-> ext. board 1, and so on
	
	static StationAttributes stationAttributes;

		
	// variables for time keeping
	static ulong sensor1_on_timer;	// time when sensor1 is detected on last time
	static ulong sensor1_off_timer; // time when sensor1 is detected off last time
	static ulong sensor1_active_lasttime; // most recent time sensor1 is activated
	static ulong sensor2_on_timer;	// time when sensor2 is detected on last time
	static ulong sensor2_off_timer; // time when sensor2 is detected off last time
	static ulong sensor2_active_lasttime; // most recent time sensor1 is activated	
	static ulong raindelay_on_lasttime;  // time when the most recent rain delay started
	static ulong flowcount_rt;		 // flow count (for computing real-time flow rate)
	static ulong flowcount_log_start; // starting flow count (for logging)

	static byte  button_timeout;				// button timeout
	static ulong checkwt_lasttime;			// time when weather was checked
	static ulong checkwt_success_lasttime; // time when weather check was successful
	static ulong powerup_lasttime;			// time when controller is powered up most recently
	static uint8_t last_reboot_cause;		// last reboot cause
	static byte  weather_update_flag; 
	// member functions
	// -- setup
	static void update_dev();		// update software for Linux instances
	static void reboot_dev(uint8_t);		// reboot the microcontroller
	static void begin();				// initialization, must call this function before calling other functions
	static byte start_network();	// initialize network with the given mac and port
	static byte start_ether();	// initialize ethernet with the given mac and port	
	static bool network_connected();		// check if the network is up
	static bool load_hardware_mac(byte* buffer, bool wired=false);	// read hardware mac address
	static time_t now_tz();
	// -- station names and attributes
	static void set_station_data(byte sid, StationData* data); // set station data
	static const char* get_station_name(byte sid) {return stationAttributes.a.d[sid].name;}
	static uint16_t parse_rfstation_code(RFStationData *data, ulong *on, ulong *off); // parse rf code into on/off/time sections
	static void switch_rfstation(RFStationData *data, bool turnon);  // switch rf station
	static void switch_remotestation(RemoteStationData *data, bool turnon); // switch remote station
	static void switch_gpiostation(GPIOStationData *data, bool turnon); // switch gpio station
	static void switch_httpstation(HTTPStationData *data, bool turnon); // switch http station

	// -- options and data storeage
	static void nvdata_load();
	static void nvdata_save();

	static void options_setup();
	static void pre_factory_reset();
	static void factory_reset();
	static void iopts_load();
	static void iopts_save();
	static bool sopt_save(byte oid, const char *buf);
	static void sopt_load(byte oid, char *buf);
	static String sopt_load(byte oid);

	static byte password_verify(char *pw);	// verify password
	
	// -- controller operation
	static void enable();						// enable controller operation
	static void disable();					// disable controller operation, all stations will be closed immediately
	static void raindelay_start();	// start raindelay
	static void raindelay_stop();		// stop rain delay
	static void detect_binarysensor_status(ulong);// update binary (rain, soil) sensor status
	static byte detect_programswitch_status(ulong); // get program switch status
	static void sensor_resetall();
	
	static uint16_t read_current(); // read current sensing value
	static uint16_t baseline_current; // resting state current

	static int detect_exp();				// detect the number of expansion boards
	static byte weekday_today();		// returns index of today's weekday (Monday is 0)

	static byte set_station_bit(byte sid, byte value); // set station bit of one station (sid->station index, value->0/1)
	static void switch_special_station(byte sid, byte value); // swtich special station
	static void clear_all_station_bits(); // clear all station bits
	static void apply_all_station_bits(); // apply all station bits (activate/deactive values)

	static int8_t send_http_request(uint32_t ip4, uint16_t port, char* p, void(*callback)(char*)=NULL, uint16_t timeout=3000);
	static int8_t send_http_request(const char* server, uint16_t port, char* p, void(*callback)(char*)=NULL, uint16_t timeout=3000);
	static int8_t send_http_request(char* server_with_port, char* p, void(*callback)(char*)=NULL, uint16_t timeout=3000);  
	// -- LCD functions
#if defined(ARDUINO) // LCD functions for Arduino
	#if defined(ESP8266)
	static void lcd_print_pgm(PGM_P str); // ESP8266 does not allow PGM_P followed by PROGMEM
	static void lcd_print_line_clear_pgm(PGM_P str, byte line);
	#else
	static void lcd_print_pgm(PGM_P PROGMEM str);						// print a program memory string
	static void lcd_print_line_clear_pgm(PGM_P PROGMEM str, byte line);
	#endif
	static void lcd_print_time(time_t t);									 // print current time
	static void lcd_print_ip(const byte *ip, byte endian);		// print ip
	static void lcd_print_mac(const byte *mac);							// print mac
	static void lcd_print_station(byte line, char c);				// print station bits of the board selected by display_board
	static void lcd_print_version(byte v);									 // print version number

	static String time2str(uint32_t t) {
		uint16_t h = hour(t);
		uint16_t m = minute(t);
		uint16_t s = second(t);
		String str = "";
		str+=h/10;
		str+=h%10;
		str+=":";
		str+=m/10;
		str+=m%10;
		str+=":";
		str+=s/10;
		str+=s%10;
		return str;
	}
	// -- UI and buttons
	static byte button_read(byte waitmode); // Read button value. options for 'waitmodes' are:
																					// BUTTON_WAIT_NONE, BUTTON_WAIT_RELEASE, BUTTON_WAIT_HOLD
																					// return values are 'OR'ed with flags
																					// check defines.h for details

	// -- UI functions --
	static void ui_set_options(int oid);		// ui for setting options (oid-> starting option index)
	static void lcd_set_brightness(byte value=1);
	static void lcd_set_contrast();

	#if defined(ESP8266)
	static IOEXP *mainio, *drio;
	static IOEXP *expanders[];
	static RCSwitch rfswitch;
	static void detect_expanders();
	static void flash_screen();
	static void toggle_screen_led();
	static void set_screen_led(byte status);	
	static byte get_wifi_mode() {return wifi_testmode ? WIFI_MODE_STA : iopts[IOPT_WIFI_MODE];}
	static byte wifi_testmode;
	static String wifi_ssid, wifi_pass;
	static void config_ip();
	static void save_wifi_ip();
	static void reset_to_ap();
	static byte state;
	#endif
	
private:
	static void lcd_print_option(int i);	// print an option to the lcd
	static void lcd_print_2digit(int v);	// print a integer in 2 digits
	static void lcd_start();
	static byte button_read_busy(byte pin_butt, byte waitmode, byte butt, byte is_holding);

	#if defined(ESP8266)
	static void latch_boost();
	static void latch_open(byte sid);
	static void latch_close(byte sid);
	static void latch_setzonepin(byte sid, byte value);
	static void latch_setallzonepins(byte value);
	static void latch_disable_alloutputs_v2();
	static void latch_setzoneoutput_v2(byte sid, byte A, byte K);
	static void latch_apply_all_station_bits();
	static byte prev_station_bits[];
	#endif
#endif // LCD functions
	static byte engage_booster;
};

// todo
#if defined(ARDUINO)
	extern EthernetServer *m_server;
	#if defined(ESP8266)
	extern ESP8266WebServer *wifi_server;
	#endif
#else
	extern EthernetServer *m_server;
#endif

#endif	// _OPENSPRINKLER_H