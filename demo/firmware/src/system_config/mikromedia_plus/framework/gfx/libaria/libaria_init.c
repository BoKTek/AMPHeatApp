/*******************************************************************************
  MPLAB Harmony Graphics Composer Generated Implementation File

  File Name:
    libaria_init.c

  Summary:
    Build-time generated implementation from the MPLAB Harmony
    Graphics Composer.

  Description:
    Build-time generated implementation from the MPLAB Harmony
    Graphics Composer.

    Created with MPLAB Harmony Version 2.06
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

SOFTWARE AND DOCUMENTATION ARE PROVIDED AS IS WITHOUT WARRANTY OF ANY KIND,
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

#include "gfx/libaria/libaria_init.h"

laScheme NewSchemeBase;
laScheme NewScheme;
laLabelWidget* LabelWidgetOverskrift;
laLabelWidget* LabelWidgetStatus;
laLabelWidget* LabelWidgetTemperature;
laLabelWidget* LabelWidgetTempResult;


static void ScreenCreate_screenMain(laScreen* screen);


int32_t libaria_initialize(void)
{
    laScreen* screen;

    laScheme_Initialize(&NewSchemeBase, GFX_COLOR_MODE_RGB_888);
    NewSchemeBase.base = 0xFFFF00;
    NewSchemeBase.highlight = 0xC8D0D4;
    NewSchemeBase.highlightLight = 0xFFFFFF;
    NewSchemeBase.shadow = 0x808080;
    NewSchemeBase.shadowDark = 0x404040;
    NewSchemeBase.foreground = 0x0;
    NewSchemeBase.foregroundInactive = 0xD6E3E7;
    NewSchemeBase.foregroundDisabled = 0x808080;
    NewSchemeBase.background = 0xFFFFFF;
    NewSchemeBase.backgroundInactive = 0xD6E3E7;
    NewSchemeBase.backgroundDisabled = 0xC8D0D4;
    NewSchemeBase.text = 0x0;
    NewSchemeBase.textHighlight = 0xFF;
    NewSchemeBase.textHighlightText = 0xFFFFFF;
    NewSchemeBase.textInactive = 0xD6E3E7;
    NewSchemeBase.textDisabled = 0x8C9294;

    laScheme_Initialize(&NewScheme, GFX_COLOR_MODE_RGB_888);
    NewScheme.base = 0xFFE6C0;
    NewScheme.highlight = 0xC8D0D4;
    NewScheme.highlightLight = 0xFFFFFF;
    NewScheme.shadow = 0x808080;
    NewScheme.shadowDark = 0x404040;
    NewScheme.foreground = 0x0;
    NewScheme.foregroundInactive = 0xD6E3E7;
    NewScheme.foregroundDisabled = 0x808080;
    NewScheme.background = 0xFFFFFF;
    NewScheme.backgroundInactive = 0xD6E3E7;
    NewScheme.backgroundDisabled = 0xC8D0D4;
    NewScheme.text = 0x0;
    NewScheme.textHighlight = 0xFF;
    NewScheme.textHighlightText = 0xFFFFFF;
    NewScheme.textInactive = 0xD6E3E7;
    NewScheme.textDisabled = 0x8C9294;

    GFX_Set(GFXF_DRAW_PIPELINE_MODE, GFX_PIPELINE_GCU);
    laContext_SetStringTable(&stringTable);

    screen = laScreen_New(LA_FALSE, LA_FALSE, &ScreenCreate_screenMain);
    laContext_AddScreen(screen);

    laContext_SetActiveScreen(0);

	return 0;
}

static void ScreenCreate_screenMain(laScreen* screen)
{
    laLayer* layer0;

    layer0 = laLayer_New();
    laWidget_SetPosition((laWidget*)layer0, 0, 0);
    laWidget_SetSize((laWidget*)layer0, 480, 272);
    laWidget_SetBackgroundType((laWidget*)layer0, LA_WIDGET_BACKGROUND_FILL);
    laWidget_SetScheme((laWidget*)layer0, &NewScheme);
    laLayer_SetBufferCount(layer0, 1);

    laScreen_SetLayer(screen, 0, layer0);

    LabelWidgetOverskrift = laLabelWidget_New();
    laWidget_SetPosition((laWidget*)LabelWidgetOverskrift, -1, 0);
    laWidget_SetSize((laWidget*)LabelWidgetOverskrift, 480, 69);
    laWidget_SetScheme((laWidget*)LabelWidgetOverskrift, &NewScheme);
    laWidget_SetBackgroundType((laWidget*)LabelWidgetOverskrift, LA_WIDGET_BACKGROUND_FILL);
    laWidget_SetBorderType((laWidget*)LabelWidgetOverskrift, LA_WIDGET_BORDER_NONE);
    laLabelWidget_SetText(LabelWidgetOverskrift, laString_CreateFromID(string_uNabtoDemo));
    laWidget_AddChild((laWidget*)layer0, (laWidget*)LabelWidgetOverskrift);

    LabelWidgetStatus = laLabelWidget_New();
    laWidget_SetPosition((laWidget*)LabelWidgetStatus, 12, 79);
    laWidget_SetSize((laWidget*)LabelWidgetStatus, 110, 36);
    laWidget_SetScheme((laWidget*)LabelWidgetStatus, &NewScheme);
    laWidget_SetBackgroundType((laWidget*)LabelWidgetStatus, LA_WIDGET_BACKGROUND_NONE);
    laWidget_SetBorderType((laWidget*)LabelWidgetStatus, LA_WIDGET_BORDER_NONE);
    laLabelWidget_SetText(LabelWidgetStatus, laString_CreateFromID(string_StringPowerOff));
    laWidget_AddChild((laWidget*)layer0, (laWidget*)LabelWidgetStatus);

    LabelWidgetTemperature = laLabelWidget_New();
    laWidget_SetPosition((laWidget*)LabelWidgetTemperature, 15, 110);
    laWidget_SetSize((laWidget*)LabelWidgetTemperature, 128, 32);
    laWidget_SetScheme((laWidget*)LabelWidgetTemperature, &NewScheme);
    laWidget_SetBackgroundType((laWidget*)LabelWidgetTemperature, LA_WIDGET_BACKGROUND_NONE);
    laWidget_SetBorderType((laWidget*)LabelWidgetTemperature, LA_WIDGET_BORDER_NONE);
    laLabelWidget_SetText(LabelWidgetTemperature, laString_CreateFromID(string_StringTemperature));
    laWidget_AddChild((laWidget*)layer0, (laWidget*)LabelWidgetTemperature);

    LabelWidgetTempResult = laLabelWidget_New();
    laWidget_SetPosition((laWidget*)LabelWidgetTempResult, 150, 111);
    laWidget_SetSize((laWidget*)LabelWidgetTempResult, 41, 32);
    laWidget_SetScheme((laWidget*)LabelWidgetTempResult, &NewScheme);
    laWidget_SetBackgroundType((laWidget*)LabelWidgetTempResult, LA_WIDGET_BACKGROUND_NONE);
    laWidget_SetBorderType((laWidget*)LabelWidgetTempResult, LA_WIDGET_BORDER_NONE);
    laLabelWidget_SetText(LabelWidgetTempResult, laString_CreateFromID(string_String23));
    laWidget_AddChild((laWidget*)layer0, (laWidget*)LabelWidgetTempResult);

}



