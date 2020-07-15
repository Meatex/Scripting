#!/bin/bash
# Get timings and settings for specified resolution
cvt=$(cvt 1920 1080 60)
cvt=${cvt##*Modeline}
#create new display mode
sudo xrandr --newmode $cvt
# make permanent
echo "sudo xrandr --newmode $cvt" >> ~/.profile 

# Get currently connect display adapter
displ=$(xrandr | grep -e " connected [^(]" | sed -e "s/\([A-Z0-9]\+\) connected.*/\1/")
res=$(echo $cvt | cut -d ' ' -f 1)
# add new mode to options
sudo xrandr --addmode $displ $res
# make option permanent
echo "sudo xrandr --addmode $displ $res" >> ~/.profile

#set display to current res
xrandr --output $displ --mode $res
