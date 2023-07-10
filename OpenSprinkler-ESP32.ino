//#define I2C_SCANNER

#include <WiFi.h>
#include <WiFiClient.h>
#include <WebServer.h>
#include <ESPmDNS.h>
#include <MCP23017.h>
#include "STASSID.h"

const char *ssid = STASSID;
const char *password = STAPSK;

WebServer server(80);

//const int led = 13;

#define MCP23017_ADDR 0x20
#define I2C_SDA 21  //	GPIO_NUM_12
#define I2C_SCL 22  //	GPIO_NUM_14
#define I2C_FREQUENCY 100000

MCP23017 mcp = MCP23017(MCP23017_ADDR);

void WiFi_init() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  Serial.println("");

  // Wait for connection
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("");
  Serial.print("Connected to ");
  Serial.println(ssid);
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

  if (MDNS.begin("esp32")) {
    Serial.println("MDNS responder started");
  }
}
int r0_state = 0;
int r1_state = 0;
void mcp_init() {
  Wire.begin(I2C_SDA, I2C_SCL, I2C_FREQUENCY);  // wake up I2C bus
  mcp.init();
  mcp.portMode(MCP23017Port::A, 0);                   //Port A as output
  mcp.portMode(MCP23017Port::B, 0);                   //Port B as output
  mcp.writeRegister(MCP23017Register::GPIO_A, 0x00);  //Reset port A
  mcp.writeRegister(MCP23017Register::GPIO_B, 0x00);  //Reset port B
  mcp.write(r0_state);
}

#ifdef I2C_SCANNER
void I2C_Scanner() {
  byte error, address;
  int nDevices;
  Serial.println("Scanning...");
  nDevices = 0;
  for (address = 1; address < 127; address++) {
    Wire.beginTransmission(address);
    error = Wire.endTransmission();
    if (error == 0) {
      Serial.print("I2C device found at address 0x");
      if (address < 16) {
        Serial.print("0");
      }
      Serial.println(address, HEX);
      nDevices++;
    } else if (error == 4) {
      Serial.print("Unknow error at address 0x");
      if (address < 16) {
        Serial.print("0");
      }
      Serial.println(address, HEX);
    }
  }
  if (nDevices == 0) {
    Serial.println("No I2C devices found\n");
  } else {
    Serial.println("done\n");
  }
  delay(3000);
}
#endif  // I2C_SCANNER

static char b_temp[128];
const char *Uptime() {
  unsigned long sec = millis() / 1000;
  unsigned long min = sec / 60;
  unsigned long hr = min / 60;
  unsigned long d = hr / 24;

  snprintf(b_temp, sizeof(b_temp), "<h2>State: %x:%x</h2><p>Uptime: %d %02d:%02d:%02d</p>", r0_state, r1_state, d, hr % 24, min % 60, sec % 60);
  return b_temp;
}

const char *html_body_start = "<html><head><style>body { background-color: #cccccc; font-family: Arial, Helvetica, Sans-Serif; Color: #000088; }</style></head><body>";
const char *html_body_end = "</body></html>";

void change_state(MCP23017& r, int& r_state, int state, bool state_on, int max_state){
    // check that there are upto 2 bits/stations on
    int n = 0, s = state;
    for(int i = 0; i < 8; i++){
      if ( s & 1)
        n++;
        s = s >> 1;
    }
    if (state >= 0 && state <= max_state && n < 3) {
      if (state_on && !(r_state & state)) {
        r_state |= state;
        r.write(r_state);
      }
      if (!state_on && (r_state & state)) {
        r_state &= ~state;
        r.write(r_state);
      }
    } else {
      snprintf(b_temp, sizeof(b_temp), "Invalid state: %x, bits: %d", state, n);
      Serial.println(b_temp);
    }
}

String message;
String uri_state_on = "/state+";
String uri_state_off = "/state-";

void handleNotFound() {
  message = html_body_start;
  String uri = server.uri();
  Serial.print("uri: ");
  Serial.println(uri);
  bool state_on = uri.startsWith(uri_state_on);
  bool state_off = uri.startsWith(uri_state_off);
  if (uri == "/") {
    message += "<h1>Welcome to OpenSprinkler-Remote</h1><p>Format of URL is:state-[state code]</p>";
  } else if (state_on || state_off) {
    String s_state(uri.c_str() + uri_state_on.length());
    int state = s_state.toInt();
    change_state(mcp, r0_state, state & 0xf, state_on, 0x8);
    change_state(mcp, r1_state, state >>  4, state_on, 0x8000);
  } else {
    Serial.print("Invalid uri: ");  Serial.println(uri);
    server.send(404, "text/plain", "File not found");
    return;
  }

  message += Uptime();
  message += html_body_end;

  server.send(200, "text/html", message);
}

void web_server_init() {
  server.onNotFound(handleNotFound);
  server.begin();
  Serial.println("HTTP server started");
}
//-------------------------------------------------------------------
void setup(void) {
  Serial.begin(115200);

  mcp_init();
  WiFi_init();
  web_server_init();
}

void loop(void) {
#ifdef I2C_SCANNER
  I2C_Scanner();
#endif
  server.handleClient();

  delay(2);  //allow the cpu to switch to other tasks
}
