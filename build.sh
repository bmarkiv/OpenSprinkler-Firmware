#!/bin/bash

while getopts ":s" opt; do
  case $opt in
    s)
	  SILENT=true
	  command shift
      ;;
  esac
done
echo "Building OpenSprinkler..."

if [ "$1" == "demo" ]; then
	echo "Installing required libraries..."
	apt-get install -y libmosquitto-dev
	echo "Compiling firmware..."
	g++ -o OpenSprinkler -DDEMO -m32 main.cpp OpenSprinkler.cpp program.cpp opensprinkler_server.cpp utils.cpp weather.cpp gpio.cpp etherport.cpp mqtt.cpp -lpthread -lmosquitto
elif [ "$1" == "osbo" ]; then
	echo "Installing required libraries..."
	apt-get install -y libmosquitto-dev
	echo "Compiling firmware..."
	g++ -o OpenSprinkler -DOSBO main.cpp OpenSprinkler.cpp program.cpp opensprinkler_server.cpp utils.cpp weather.cpp gpio.cpp etherport.cpp mqtt.cpp -lpthread -lmosquitto
elif [ "$1" == "app" ]; then
	echo "Building app.js..."
	cat js/jquery.js  > data/js/app.js
	cat js/libs.js   >> data/js/app.js
	cat js/hasher.js >> data/js/app.js
	cat js/map.js    >> data/js/app.js
	cat js/main.js   >> data/js/app.js


	exit 0	
elif [ "$1" == "64" ]; then
	CPLUS_INCLUDE_PATH="/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/cores/esp8266"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/tools/sdk/include"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/toolchain-xtensa/xtensa-lx106-elf/include"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/variants/nodemcu"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/libraries/Wire"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/libraries/ESP8266WiFi/src"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/libraries/SPI"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/libraries/Ethernet/src"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/tools/sdk/lwip2/include"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/Documents/Arduino/OpenSprinkler/.pio/libdeps/esp12e/rc-switch"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/Documents/Arduino/OpenSprinkler/.pio/libdeps/esp12e/PubSubClient/src"
	CPLUS_INCLUDE_PATH="$CPLUS_INCLUDE_PATH:/mnt/c/Users/borys/.platformio/packages/framework-arduinoespressif8266/libraries/ESP8266WebServer/src"
	CPLUS_INCLUDE_PATH=""
	export CPLUS_INCLUDE_PATH
	g++ -g -std=c++11 -o OpenSprinkler -D_GLIBCXX_GCC_GTHR_POSIX_H -D_PTHREAD_H -DLWIP_FEATURES=1 -DLWIP_OPEN_SRC -DLWIP_IPV6=0 -DTCP_MSS=536 -DESP8266_ -DF_CPU=1000000000L -DARDUINO_=150 -DDEBUG -DDEMO main.cpp OpenSprinkler.cpp program.cpp opensprinkler_server.cpp utils.cpp weather.cpp gpio.cpp etherport.cpp mqtt.cpp -lpthread -lmosquitto
	exit 0
else
	echo "Installing required libraries..."
	apt-get install -y libmosquitto-dev
	echo "Compiling firmware..."
	g++ -o OpenSprinkler -DOSPI main.cpp OpenSprinkler.cpp program.cpp opensprinkler_server.cpp utils.cpp weather.cpp gpio.cpp etherport.cpp mqtt.cpp -lpthread -lmosquitto
fi

if [ ! "$SILENT" = true ] && [ -f OpenSprinkler.launch ] && [ ! -f /etc/init.d/OpenSprinkler.sh ]; then

	read -p "Do you want to start OpenSprinkler on startup? " -n 1 -r
	echo

	if [[ ! $REPLY =~ ^[Yy]$ ]]; then
		exit 0
	fi

	echo "Adding OpenSprinkler launch script..."

	# Get current directory (binary location)
	pushd `dirname $0` > /dev/null
	DIR=`pwd`
	popd > /dev/null

	# Update binary location in start up script
	sed -e 's,\_\_OpenSprinkler\_Path\_\_,'"$DIR"',g' OpenSprinkler.launch > OpenSprinkler.sh

	# Make file executable
	chmod +x OpenSprinkler.sh

	# Move start up script to init.d directory
	sudo mv OpenSprinkler.sh /etc/init.d/

	# Add to auto-launch on system startup
	sudo update-rc.d OpenSprinkler.sh defaults

	# Start the deamon now
	sudo /etc/init.d/OpenSprinkler.sh start

fi

echo "Done!"
