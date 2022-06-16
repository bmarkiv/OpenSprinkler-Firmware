#include "defines.h"
#include "utils.h"
#if defined(ARDUINO) // headers for ESP8266
#include <Arduino.h>
#endif

struct StationAttrib {	// station attributes
	byte mas:1;
	byte igs:1;	// ignore sensor 1
	byte mas2:1;
	byte dis:1;
	byte seq:1;
	byte igs2:1;// ignore sensor 2
	byte igrd:1;// ignore rain delay
	byte unused:1;
	
	byte gid:4; // group id: reserved for the future
	byte dummy:4;
	byte reserved[2]; // reserved bytes for the future
}; // total is 4 bytes so far

/** Station data structure */
struct StationData {
	char name[STATION_NAME_SIZE];
	StationAttrib attrib;
	byte type; // station type
	byte sped[STATION_SPECIAL_DATA_SIZE]; // special station data
};
/** Non-volatile data structure */
struct NVConData {
	uint16_t sunrise_time;	// sunrise time (in minutes)
	uint16_t sunset_time;		// sunset time (in minutes)
	uint32_t rd_stop_time;	// rain delay stop time
	uint32_t external_ip;		// external ip
	uint8_t  reboot_cause;	// reboot cause
};

/** RF station data structures - Must fit in STATION_SPECIAL_DATA_SIZE */
struct RFStationData {
	byte on[6];
	byte off[6];
	byte timing[4];
};

/** Remote station data structures - Must fit in STATION_SPECIAL_DATA_SIZE */
struct RemoteStationData {
	byte ip[8];
	byte port[4];
	byte sid[2];
};

/** GPIO station data structures - Must fit in STATION_SPECIAL_DATA_SIZE */
struct GPIOStationData {
	byte pin[2];
	byte active;
};

/** HTTP station data structures - Must fit in STATION_SPECIAL_DATA_SIZE */
struct HTTPStationData {
	byte data[STATION_SPECIAL_DATA_SIZE];
};

/** Volatile controller status bits */
struct ConStatus {
	byte enabled:1;					// operation enable (when set, controller operation is enabled)
	byte rain_delayed:1;			// rain delay bit (when set, rain delay is applied)
	byte sensor1:1;					// sensor1 status bit (when set, sensor1 on is detected)
	byte program_busy:1;			// HIGH means a program is being executed currently
	byte has_curr_sense:1;		    // HIGH means the controller has a current sensing pin
	byte safe_reboot:1;				// HIGH means a safe reboot has been marked
	byte req_ntpsync:1;				// request ntpsync
	byte req_network:1;				// request check network
	byte display_board:5;			// the board that is being displayed onto the lcd
	byte network_fails:3;			// number of network fails
	byte mas:8;						// master station index
	byte mas2:8;					// master2 station index
	byte sensor2:1;					// sensor2 status bit (when set, sensor2 on is detected)
	byte sensor1_active:1;		    // sensor1 active bit (when set, sensor1 is activated)
	byte sensor2_active:1;		    // sensor2 active bit (when set, sensor2 is activated)
	byte req_mqtt_restart:1;		// request mqtt restart
};

struct StationAttributes_ {
    StationData d   [MAX_NUM_BOARDS];

    byte attrib_mas [MAX_NUM_BOARDS];
    byte attrib_igs [MAX_NUM_BOARDS];
    byte attrib_mas2[MAX_NUM_BOARDS];
    byte attrib_igs2[MAX_NUM_BOARDS];
    byte attrib_igrd[MAX_NUM_BOARDS];
    byte attrib_dis [MAX_NUM_BOARDS];
    byte attrib_seq [MAX_NUM_BOARDS];
    byte attrib_spe [MAX_NUM_BOARDS];

    void to_attrib(){
        int bid, s, sid;
        byte ty;
        for(bid=0;bid<MAX_NUM_BOARDS;bid++) {
            StationAttrib& at = d[bid].attrib;
            attrib_mas [bid] |= at.mas ;
            attrib_igs [bid] |= at.igs ;
            attrib_mas2[bid] |= at.mas2;
            attrib_igs2[bid] |= at.igs2;
            attrib_igrd[bid] |= at.igrd;
            attrib_dis [bid] |= at.dis ;
            attrib_seq [bid] |= at.seq ;
            if(d[bid].type!=STN_TYPE_STANDARD) {
                attrib_spe[bid] |= 1;
            }
        }
    }

    void from_attrib(){
        // re-package attribute bits and save
        byte bid, s, sid=0;
        byte ty = STN_TYPE_STANDARD;
        for(bid=0;bid<MAX_NUM_BOARDS;bid++) {
            StationAttrib& at = d[bid].attrib;
            at.mas = attrib_mas [bid] ;
            at.igs = attrib_igs [bid] ;
            at.mas2= attrib_mas2[bid];
            at.igs2= attrib_igs2[bid];
            at.igrd= attrib_igrd[bid];			 
            at.dis = attrib_dis [bid] ;
            at.seq = attrib_seq [bid] ;
            at.gid = 0;
            if(attrib_spe[bid]==0) {
                // if station special bit is 0, make sure to write type STANDARD
                d[bid].type = STN_TYPE_STANDARD;
            }
        }        
    }
};

class StationAttributes {
public:
    StationAttributes_ a;

	/** Get station data */
	void get_station_data(byte sid, StationData* data) {
		file_read_block(STATIONS_FILENAME, data, (uint32_t)sid*sizeof(StationData), sizeof(StationData));
	}

	/** Get station name */
	void get_station_name(byte sid, char tmp[]) {
        strcpy(tmp, a.d[sid].name);
	}

	void attribs_save() {
        file_write_block(STATIONS_FILENAME, &a, 0, sizeof(a));
	}

	void attribs_load() {
        file_read_block(STATIONS_FILENAME, &a, 0, sizeof(a));
    }
};