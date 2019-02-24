/*******************************************************************************
  MPLAB Harmony Application Source File
  
  Company:
    Microchip Technology Inc.
  
  File Name:
    app.c

  Summary:
    This file contains the source code for the MPLAB Harmony application.

  Description:
    This file contains the source code for the MPLAB Harmony application.  It 
    implements the logic of the application's state machine and it may call 
    API routines of other MPLAB Harmony modules in the system, such as drivers,
    system services, and middleware.  However, it does not call any of the
    system interfaces (such as the "Initialize" and "Tasks" functions) of any of
    the modules in the system or make any assumptions about when those functions
    are called.  That is the responsibility of the configuration-specific system
    files.
 *******************************************************************************/

// DOM-IGNORE-BEGIN
/*******************************************************************************
Copyright (c) 2013-2014 released Microchip Technology Inc.  All rights reserved.

Microchip licenses to you the right to use, modify, copy and distribute
Software only when embedded on a Microchip microcontroller or digital signal
controller that is integrated into your product or third party product
(pursuant to the sublicense terms in the accompanying license agreement).

You should refer to the license agreement accompanying this Software for
additional information regarding your rights and obligations.

SOFTWARE AND DOCUMENTATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND,
EITHER EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION, ANY WARRANTY OF
MERCHANTABILITY, TITLE, NON-INFRINGEMENT AND FITNESS FOR A PARTICULAR PURPOSE.
IN NO EVENT SHALL MICROCHIP OR ITS LICENSORS BE LIABLE OR OBLIGATED UNDER
CONTRACT, NEGLIGENCE, STRICT LIABILITY, CONTRIBUTION, BREACH OF WARRANTY, OR
OTHER LEGAL EQUITABLE THEORY ANY DIRECT OR INDIRECT DAMAGES OR EXPENSES
INCLUDING BUT NOT LIMITED TO ANY INCIDENTAL, SPECIAL, INDIRECT, PUNITIVE OR
CONSEQUENTIAL DAMAGES, LOST PROFITS OR LOST DATA, COST OF PROCUREMENT OF
SUBSTITUTE GOODS, TECHNOLOGY, SERVICES, OR ANY CLAIMS BY THIRD PARTIES
(INCLUDING BUT NOT LIMITED TO ANY DEFENSE THEREOF), OR OTHER SIMILAR COSTS.
 *******************************************************************************/
// DOM-IGNORE-END


// *****************************************************************************
// *****************************************************************************
// Section: Included Files 
// *****************************************************************************
// *****************************************************************************

#include "app.h"
#include <bsp.h>
#include <crypto/crypto.h>
#include <stdint.h>
#include <stdlib.h>
#include <unabto/unabto_common_main.h>
#include <unabto/unabto_types.h>
#include <unabto/unabto_app.h>
#include <unabto/unabto_util.h>
#include <unabto/unabto_app_adapter.h>
#include <unabto/unabto_hmac_sha256.h>
#include <unabto/unabto_prf.h>
#include <modules/fingerprint_acl/fp_acl_ae.h>
#include <modules/fingerprint_acl/fp_acl_memory.h>
#include <modules/fingerprint_acl/fp_acl_file.h>


// Function prototypes
uint8_t setLed(uint8_t led_id, uint8_t led_on);
uint8_t readLed(uint8_t led_id);


APP_DATA appData;

typedef enum { HPM_COOL = 0,
               HPM_HEAT = 1,
               HPM_CIRCULATE = 2,
               HPM_DEHUMIDIFY = 3} heatpump_mode_t;

    static uint8_t heatpump_state_ = 1;
    static uint32_t heatpump_mode_ = HPM_HEAT;
    static int32_t heatpump_room_temperature_ = 19;
    static int32_t heatpump_target_temperature_ = 23;

#define DEVICE_NAME_DEFAULT "AMP Heat App"
#define MAX_DEVICE_NAME_LENGTH 50

    static char device_name_[MAX_DEVICE_NAME_LENGTH];
    static const char* device_product_ = "ACME 9002 Heatpump";
    static const char* device_icon_ = "chip-small.png";
    static const char* device_interface_id_ = "317aadf2-3137-474b-8ddb-fea437c424f4";
    static uint16_t device_interface_version_major_ = 1;
    static uint16_t device_interface_version_minor_ = 0;

    static struct fp_acl_db db_;
    struct fp_mem_persistence fp_file_;

#define REQUIRES_GUEST FP_ACL_PERMISSION_NONE
#define REQUIRES_OWNER FP_ACL_PERMISSION_ADMIN

    
const char* idSuffix = ".starterkit.u.nabto.net";
char idBuffer[64];


void debug_dump_acl() {
    void* it = db_.first();
    if (!it) {
        NABTO_LOG_INFO(("ACL is empty (no paired users)"));
    } else {
        NABTO_LOG_INFO(("ACL entries:"));
        while (it != NULL) {
            struct fp_acl_user user;
            fp_acl_db_status res = db_.load(it, &user);
            if (res != FP_ACL_DB_OK) {
                NABTO_LOG_WARN(("ACL error %d\n", res));
                return;
            }
            if (user.fp.hasValue) {
                NABTO_LOG_INFO((" - %s [%02x:%02x:%02x:%02x:...]: %04x",
                                user.name,
                                user.fp.value.data[0], user.fp.value.data[1], user.fp.value.data[2], user.fp.value.data[3],
                                user.permissions));
            }
            it = db_.next(it);
        }
    }
}

void demo_init() {
    struct fp_acl_settings default_settings;
    NABTO_LOG_WARN(("WARNING: Remote access to the device is turned on by default. Please read TEN36 \"Security in Nabto Solutions\" to understand the security implications."));
    default_settings.systemPermissions =
        FP_ACL_SYSTEM_PERMISSION_PAIRING |
        FP_ACL_SYSTEM_PERMISSION_LOCAL_ACCESS |
        FP_ACL_SYSTEM_PERMISSION_REMOTE_ACCESS;
    default_settings.defaultUserPermissions =
        FP_ACL_PERMISSION_LOCAL_ACCESS;
    default_settings.firstUserPermissions =
        FP_ACL_PERMISSION_ADMIN |
        FP_ACL_PERMISSION_LOCAL_ACCESS |
        FP_ACL_PERMISSION_REMOTE_ACCESS;

    if (fp_acl_file_init("persistence.bin", "tmp.bin", &fp_file_) != FP_ACL_DB_OK) {
        NABTO_LOG_ERROR(("cannot load acl file"));
        exit(1);
    }
    fp_mem_init(&db_, &default_settings, &fp_file_);
    fp_acl_ae_init(&db_);
    snprintf(device_name_, sizeof(device_name_), DEVICE_NAME_DEFAULT);
    //updateLed();
    setLed(1, heatpump_state_);
    debug_dump_acl();
}

void demo_application_tick() {
    static uint16_t ticks_ = 0;
    if (ticks_ > 60000) {
        if (heatpump_room_temperature_ < heatpump_target_temperature_) {
	    heatpump_room_temperature_++;
        } else if (heatpump_room_temperature_ > heatpump_target_temperature_) {
	    heatpump_room_temperature_--;
        }
        ticks_ = 0;
        static char charBuff[10];
        laString str;
        char number[2];
        sprintf(number, "%u", heatpump_room_temperature_);
        str = laString_CreateFromCharBuffer(number, GFXU_StringFontIndexLookup(&stringTable, string_String0123456789, 0));
        laLabelWidget_SetText(LabelWidgetTempResult, str);
        laString_Destroy(&str);
    }
    ticks_++;
}


void APP_Initialize ( void )
{
    /* Place the App state machine in its initial state. */
    appData.state = APP_STATE_INIT;
    //RESET_BAROn();
}

void APP_Tasks ( void )
{
    /* Check the application's current state. */
    switch ( appData.state )
    {
        /* Application's initial state. */
        case APP_STATE_INIT:
        {            
            SYS_STATUS tcpipStat = TCPIP_STACK_Status(sysObj.tcpip);
            if(tcpipStat == SYS_STATUS_READY) {
                appData.state = APP_STATE_INIT_UNABTO;
            }
            break;
        }

        case APP_STATE_INIT_UNABTO:
        {
            unabto_udp_debug_init("192.168.1.103", 4242);
            TCPIP_NET_HANDLE defaultIf = TCPIP_STACK_NetDefaultGet();
            const uint8_t* physicalAddress = TCPIP_STACK_NetAddressMac(defaultIf);
            if (physicalAddress == NULL) {
                NABTO_LOG_FATAL(("physical address should be present"));
                break;
            }
            nabto_main_setup* nms;
            nms = unabto_init_context();
            memset(idBuffer, 0, sizeof(idBuffer));
            sprintf(idBuffer, "%02x%02x%02x%s", physicalAddress[3], physicalAddress[4], physicalAddress[5], idSuffix);
            nms->id = idBuffer;

            nms->cryptoSuite = CRYPT_W_AES_CBC_HMAC_SHA256;
            nms->secureAttach = 1;
            nms->secureData = 1;
            memset(nms->presharedKey, 0, PRE_SHARED_KEY_SIZE);

            if (!unabto_init()) {
                NABTO_LOG_FATAL(("could not initialize nabto"));
                break;
            }
            demo_init();
            appData.state = APP_STATE_SERVICE_TASKS;
        }
        
        case APP_STATE_SERVICE_TASKS:
        {            
            unabto_tick();
            demo_application_tick();
            break;
        }

        /* The default state should never be executed. */
        default:
        {
            /* TODO: Handle error in application's state machine. */
            break;
        }
    }
}

int copy_buffer(unabto_query_request* read_buffer, uint8_t* dest, uint16_t bufSize, uint16_t* len) {
    uint8_t* buffer;
    if (!(unabto_query_read_uint8_list(read_buffer, &buffer, len))) {
        return AER_REQ_TOO_SMALL;
    }
    if (*len > bufSize) {
        return AER_REQ_TOO_LARGE;
    }
    memcpy(dest, buffer, *len);
    return AER_REQ_RESPONSE_READY;
}

int copy_string(unabto_query_request* read_buffer, char* dest, uint16_t destSize) {
    uint16_t len;
    int res = copy_buffer(read_buffer, (uint8_t*)dest, destSize-1, &len);
    if (res != AER_REQ_RESPONSE_READY) {
        return res;
    }
    dest[len] = 0;
    return AER_REQ_RESPONSE_READY;
}


int write_string(unabto_query_response* write_buffer, const char* string) {
    return unabto_query_write_uint8_list(write_buffer, (uint8_t *)string, strlen(string));
}

bool allow_client_access(nabto_connect* connection) {
    bool local = connection->isLocal;
    bool allow = fp_acl_is_connection_allowed(connection) || local;
    NABTO_LOG_INFO(("Allowing %s connect request: %s", (local ? "local" : "remote"), (allow ? "yes" : "no")));
    debug_dump_acl();
    return allow;
}


/***************** The uNabto application logic *****************
 * This is where the user implements his/her own functionality
 * to the device. When a Nabto message is received, this function
 * gets called with the message's request id and parameters.
 * Afterwards a user defined message can be sent back to the
 * requesting browser.
 ****************************************************************/
application_event_result application_event(application_request* request, unabto_query_request* query_request,  unabto_query_response* query_response) {
//application_event_result application_event(application_request* request, unabto_query_request* read_buffer, unabto_query_response* write_buffer) {
    
    NABTO_LOG_INFO(("Nabto application_event: %u", request->queryId));
    debug_dump_acl();

    // handle requests as defined in interface definition shared with
    // client - for the default demo, see
    // https://github.com/nabto/ionic-starter-nabto/blob/master/www/nabto/unabto_queries.xml

    application_event_result res;

    if (request->queryId >= 11000 && request->queryId < 12000) {
        // default PPKA access control (see unabto/src/modules/fingerprint_acl/fp_acl_ae.c)
        application_event_result res = fp_acl_ae_dispatch(11000, request, query_request, query_response);
        NABTO_LOG_INFO(("ACL request [%d] handled with status %d", request->queryId, res));
        debug_dump_acl();
        return res;
    }

    switch(request->queryId) {
        case 0: {
            // get_interface_info.json
            if (!write_string(query_response, device_interface_id_)) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint16(query_response, device_interface_version_major_)) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint16(query_response, device_interface_version_minor_)) return AER_REQ_RSP_TOO_LARGE;
            return AER_REQ_RESPONSE_READY;
        }
        
        case 10000: {
            // get_public_device_info.json
            if (!write_string(query_response, device_name_)) return AER_REQ_RSP_TOO_LARGE;
            if (!write_string(query_response, device_product_)) return AER_REQ_RSP_TOO_LARGE;
            if (!write_string(query_response, device_icon_)) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint8(query_response, fp_acl_is_pair_allowed(request))) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint8(query_response, fp_acl_is_user_paired(request))) return AER_REQ_RSP_TOO_LARGE; 
            if (!unabto_query_write_uint8(query_response, fp_acl_is_user_owner(request))) return AER_REQ_RSP_TOO_LARGE;
            return AER_REQ_RESPONSE_READY;
        }
        
        case 10010:{
            // set_device_info.json
            if (!fp_acl_is_request_allowed(request, REQUIRES_OWNER)) return AER_REQ_NO_ACCESS;
            int res = copy_string(query_request, device_name_, sizeof(device_name_));
            if (res != AER_REQ_RESPONSE_READY) return res;
            if (!write_string(query_response, device_name_)) return AER_REQ_RSP_TOO_LARGE;
            return AER_REQ_RESPONSE_READY;
        }
        
        case 20000: {
            // heatpump_get_full_state.json
            if (!fp_acl_is_request_allowed(request, REQUIRES_GUEST)) return AER_REQ_NO_ACCESS;
            if (!unabto_query_write_uint8(query_response, heatpump_state_)) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint32(query_response, heatpump_mode_)) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint32(query_response, (uint32_t)heatpump_target_temperature_)) return AER_REQ_RSP_TOO_LARGE;
            if (!unabto_query_write_uint32(query_response, (uint32_t)heatpump_room_temperature_)) return AER_REQ_RSP_TOO_LARGE;
            return AER_REQ_RESPONSE_READY;
        }
        
        case 20010: {
            // heatpump_set_activation_state.json
            if (!fp_acl_is_request_allowed(request, REQUIRES_GUEST)) return AER_REQ_NO_ACCESS;
            if (!unabto_query_read_uint8(query_request, &heatpump_state_)) return AER_REQ_TOO_SMALL;
            if (!unabto_query_write_uint8(query_response, heatpump_state_)) return AER_REQ_RSP_TOO_LARGE;
            NABTO_LOG_INFO(("Got (and returned) state %d", heatpump_state_));
            // Set onboard led according to request
            setLed(1, heatpump_state_);
            return AER_REQ_RESPONSE_READY;
        }
        
        case 20020: {
            // heatpump_set_target_temperature.json
            if (!fp_acl_is_request_allowed(request, REQUIRES_GUEST)) return AER_REQ_NO_ACCESS;
            if (!unabto_query_read_uint32(query_request, (uint32_t*)(&heatpump_target_temperature_))) return AER_REQ_TOO_SMALL;
            if (!unabto_query_write_uint32(query_response, (uint32_t)heatpump_target_temperature_)) return AER_REQ_RSP_TOO_LARGE;
            setLed(1, heatpump_state_);
            return AER_REQ_RESPONSE_READY;
        }
        
        case 20030: {
            // heatpump_set_mode.json
            if (!fp_acl_is_request_allowed(request, REQUIRES_GUEST)) return AER_REQ_NO_ACCESS;
            if (!unabto_query_read_uint32(query_request, &heatpump_mode_)) return AER_REQ_TOO_SMALL;
            if (!unabto_query_write_uint32(query_response, heatpump_mode_)) return AER_REQ_RSP_TOO_LARGE;
            return AER_REQ_RESPONSE_READY;
        }
        
        default: {
            NABTO_LOG_WARN(("Unhandled query id: %u", request->queryId));
            return AER_REQ_INV_QUERY_ID;
        }
    }
    return AER_REQ_INV_QUERY_ID;
}

// Set first onboard LED and return state,
// only using ID #1 in this simple example
uint8_t setLed(uint8_t led_id, uint8_t led_on)
{
    if (led_id == 1) {
        BSP_LED_STATE state = BSP_LED_STATE_OFF;
        if (led_on) {
            state = BSP_LED_STATE_ON;
            laLabelWidget_SetText(LabelWidgetStatus, laString_CreateFromID(string_StringPowerOn));
        }else
        {
            laLabelWidget_SetText(LabelWidgetStatus, laString_CreateFromID(string_StringPowerOff));
        }
        BSP_LEDStateSet(BSP_LED_1, state);
        return readLed(led_id);
    }
    return -1;
}

// Return first onboard LED state,
// only using ID #1 in this simple example
uint8_t readLed(uint8_t led_id) {
    if (led_id == 1) {
        BSP_LED_STATE state = BSP_LEDStateGet(BSP_LED_1);
        if (state == BSP_LED_STATE_ON) {
            return 1;
        } else {
            return 0;
        }
    }
    return -1;
}

 

/*******************************************************************************
 End of File
 */
