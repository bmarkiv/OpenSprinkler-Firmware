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
	cat js/main.js   >> data/js/app.js


	exit 0	
elif [ "$1" == "64" ]; then
	echo "Building app.js..."
	rm  data/js/app.js.gz
	cat js/jquery.js  > data/js/app.js
	cat js/libs.js   >> data/js/app.js
	cat js/main.js   >> data/js/app.js
	gzip                data/js/app.js
	rm *.dat
	g++ -g -std=c++11 -o OpenSprinkler -DDEMO -D_GLIBCXX_GCC_GTHR_POSIX_H -D_PTHREAD_H -DLWIP_FEATURES=1 -DLWIP_OPEN_SRC -DLWIP_IPV6=0 -DTCP_MSS=536 -DESP8266_ -DF_CPU=1000000000L -DARDUINO_=150 -DDEBUG -DDEMO main.cpp OpenSprinkler.cpp program.cpp opensprinkler_server.cpp utils.cpp weather.cpp gpio.cpp etherport.cpp mqtt.cpp -lpthread -lmosquitto
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
