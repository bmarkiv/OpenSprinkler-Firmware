#define WHITE 1
#define BLACK 0

struct SSD1306
{
    SSD1306(uint8_t _addr, uint8_t _sda, uint8_t _scl) {}
    void flipScreenVertically(){}
    void setFont(const byte* font){}
    void print(String &t)                       {}//{Serial.println(t);}
    void print(const char* t)                   {}//{Serial.println((const char *)t);}
    void print(const __FlashStringHelper * t)   {}//{Serial.println((const char *)t);}
    void print(int t){}
    void print(int p1, int p2){}
    void write(char* t){}
    void init(){}
    void begin(){}
    void noBlink(){}
    void clear(){}
    void display(){}
    void setColor(int c){}
    void displayOn(){}
    void displayOff(){}
    void setBrightness(int c){}
    void fillRect(int p1, int p2, int p3, int p4){}
    void fillCircle(int p1, int p2, int p3){}
    void drawXbm(int cx, int cy, int fontWidth, int fontHeight, const byte* custom_chars){}
    void drawString(int cx, int cy, String s){}
};
