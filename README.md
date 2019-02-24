## AMPHeatApp
PIC32 demo using the harmony framework with a Mikroelektronika mikromedia+ board.


The version numbers below is the versions the software has been built
and tested with, newer versions may work.

# Requirements
  1. Microchip XC32 2.15
  2. Microchip Harmony 2.06
  3. Microchip MPLAB X IDE 4.15
  4. Microchip ICD 3 or newer.
  6. Mikroelektronika print mikromedia Plus for PIC32MX7 https://www.mikroe.com/mikromedia-4-pic32mx7
  7. Mikroelektronika print mikromedia Plus for PIC32MX7 shield https://www.mikroe.com/mikromedia-4-pic32mx7-shield
    

In the MPLAB X IDE please make sure that MPLAB Harmony Configurator is installed in tools->plugins in the Installed tab

# Prerequisites
You must be able to make a simple hallo world Harmony project in the MPLAB X IDE similar to:
http://ww1.microchip.com/downloads/en/DeviceDoc/MPLAB%20Harmony%20Tutorial%20-%20Creating%20an%20Application_v111.pdf

## How to program the device

Clone this github repository recursively such that submodules get checked out.

  * git clone --recursive https://github.com/BoKTek/mikromedia-plus-PIC32MX795F512L
  * open the projects in demo/firmware/ folders with MPLAB X
  * You can also clone from MPLAB X directly, copy above link and in MPLAB X goto 'Team -> Git -> Clone' and pasta the link into
    Repository URL.
  * Generate the Harmony configurator code, this is rather tricky if you are new to harmony/mplab X. 
    Set the project as the main project.
    Goto the harmony configurator `Tools -> Embedded -> MPLAB Harmony configurator` when the ide asks for the harmony folder
    give the folder where you installed harmony, if unsure run the harmony installer again.
    Now open the \\\demo\firmware\src\system_config\mikromedia_plus.mhc configuration file and click on the code generation button.
    The harmony step fails easily because of the complexity and if any component in the system has been updated.
  * Connect the mikromedia board to the ICD3 of 4 programmer.
  * compile with XC32 version 2.15
  * flash target
  
## How to use the demo

  1. Flash the device as explained in the above section. 
  2. Open the Nabto Client app from the android or ios app store.
  3. Discover the device and connect to it.


## Quirks

If you are starting a new project based on this increase 
the TCPIP_DNS_CLIENT_MAX_HOSTNAME_LEN to something more than 32 bytes 
if your hostnames are longer than that.


## Test level

The code is smoke tested.
