/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "csyslogd.h"
#include "os_net/os_net.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <libxml/parser.h>

#include "cJSON.h"

/* Global variables */
char __shost[512];
char __shost_long[512];
char __vin[64];
char __soft_version[VERSION_MAX_SIZE];
char __strategy_version[VERSION_MAX_SIZE];

enum sysinfo_e
{
	e_device_id = 0,
	e_sysinfo_e_max
};

struct xmlItem_s
{
	char *name;
	char content[64];
};

struct xmlItem_s nodeItem[e_sysinfo_e_max]=
{
	{"device_id",{0}},
};

void get_deviceId(const char *filename, char *const out)
{
	int i = 0;
	xmlDocPtr doc;
	xmlNodePtr curNode;
	xmlChar *szKey;
	doc = xmlReadFile(filename, "UTF-8", XML_PARSE_RECOVER);
	if(doc == NULL)
	{
		return;
	}
	curNode = xmlDocGetRootElement(doc);
	if(curNode == NULL)
	{
		fprintf(stderr, "error:empty document\n");
		xmlFreeDoc(doc);
		return;
	}

	if(xmlStrcmp(curNode->name, BAD_CAST"sysinfo"))
	{
		fprintf(stderr, "document of the wrong type, sysinfo node != sysinfo\n");
		xmlFreeDoc(doc);
		return;
	}

	curNode = curNode->xmlChildrenNode;
	while(curNode != NULL)
	{
		for (i = 0; i < e_sysinfo_e_max; i++)
		{

			if(!xmlStrcmp(curNode->name, (const xmlChar *)nodeItem[i].name))
			{
			    szKey = xmlNodeGetContent(curNode);
			    strcpy(nodeItem[i].content,(char*)szKey);
			    printf("%s=%s\n", nodeItem[i].name, nodeItem[i].content);
			    xmlFree(szKey);
			}
		}
		curNode = curNode->next;
	}
	xmlFreeDoc(doc);
    memcpy(out, nodeItem[e_device_id].content, strlen(nodeItem[e_device_id].content)+1);
}

int GetVersionInFile(const char *file, char *softVersion, char *strategyVersion)
{
    if (!file || !softVersion || !strategyVersion) {
        merror("INFO: parameter error.");
        return 0;
    }

    FILE *fp;
    fp = fopen(file, "r");
    if (!fp) {
        merror("INFO: file open error: %s", file);
        return 0;
    }

    if (fgets(softVersion, VERSION_MAX_SIZE, fp) != NULL) {
        char* n = strchr(softVersion, '\n');
        if (n) {
            *n = '\0';
        }
    } else {
        merror("INFO: softVersion error.");
    }

    if (fgets(strategyVersion, VERSION_MAX_SIZE, fp) != NULL) {
        char* n = strchr(strategyVersion, '\n');
        if (n) {
            *n = '\0';
        }
    } else {
        merror("INFO: strategyVersion error.");
    }

    fclose(fp);
    return 1;
}

int GetPath(const char *file, char *path)
{
    if (!file || !path) {
        return 0;
    }
    const char* first = strchr(file, '/');
	const char* last = strrchr(file, '/');
    if (!first || !last) {
        return 0;
	}
    const char* version = "VERSION";
    memcpy(path, first, last - first + 1);
	memcpy(path + strlen(path), version, strlen(version) + 1);
    return 1;
}

/* Monitor the alerts and send them via syslog
 * Only return in case of error
 */
void OS_CSyslogD(SyslogConfig **syslog_config)
{
    int s = 0;
    time_t tm;
    struct tm *p;
    int tries = 0;
    file_queue *fileq;
    alert_data *al_data;

    /* Get current time before starting */
    tm = time(NULL);
    p = localtime(&tm);

    /* Initialize file queue to read the alerts */
    os_calloc(1, sizeof(file_queue), fileq);
    while ( (Init_FileQueue(fileq, p, 0) ) < 0 ) {
        tries++;
        if ( tries > OS_CSYSLOGD_MAX_TRIES ) {
            merror("%s: ERROR: Could not open queue after %d tries, exiting!",
                   ARGV0, tries
                  );
            exit(1);
        }
        sleep(1);
    }
    debug1("%s: INFO: File queue connected.", ARGV0 );

    /* Connect to syslog */
    s = 0;
    while (syslog_config[s]) {
        syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port,
                                                 syslog_config[s]->server);
        if (syslog_config[s]->socket < 0) {
            merror(CONNS_ERROR, ARGV0, syslog_config[s]->server);
        } else {
            merror("%s: INFO: Forwarding alerts via syslog to: '%s:%s'.",
                   ARGV0, syslog_config[s]->server, syslog_config[s]->port);
        }

        s++;
    }
    // while (syslog_config[s]) {
    //     struct hostent *hostent = NULL;
    //     hostent = gethostbyname(syslog_config[s]->server);
    //     int i = 0;
    //     while(hostent->h_addr_list[i] != NULL){
    //         char *ipaddr = inet_ntoa(*((struct in_addr *)hostent->h_addr_list[i]));

    //         syslog_config[s]->socket = OS_ConnectUDP(syslog_config[s]->port,
    //                                                 ipaddr);
    //         if (syslog_config[s]->socket < 0) {
    //             merror(CONNS_ERROR, ARGV0, syslog_config[s]->server);
    //             merror(CONNS_ERROR, ARGV0, ipaddr);
    //         } else {
    //             merror("%s: INFO: Forwarding alerts via syslog to: '%s:%s:%s'.",
    //                 ARGV0, syslog_config[s]->server, ipaddr, syslog_config[s]->port);
    //             break;
    //         }
    //         i++;
    //     }
    //     s++;
    // }

    /* Get VIN */
    get_deviceId(VIN_FILE_PATH, __vin);
    /* Get version */
    int ret = GetVersionInFile(VERSION_FILE_PATH, __soft_version, __strategy_version);
    if (ret) {
        merror("%s: INFO: __soft_version: %s.", ARGV0, __soft_version);
        merror("%s: INFO: __strategy_version: %s.", ARGV0, __strategy_version);
    } else {
        memcpy(__soft_version, "3.7.0", 6);
        memcpy(__strategy_version, "1.0.0", 6);
    }

    /* Infinite loop reading the alerts and inserting them */
    while (1) {
        tm = time(NULL);
        p = localtime(&tm);

        /* Get message if available (timeout of 5 seconds) */
        al_data = Read_FileMon(fileq, p, 5);
        if (!al_data) {
            continue;
        }

        /* Send via syslog */
        s = 0;
        while (syslog_config[s]) {
            OS_Alert_SendSyslog(al_data, syslog_config[s]);

            unsigned int sendFrequency = 0;
            sendFrequency = syslog_config[s]->frequency;
            if (sendFrequency != 0) {
                sleep(sendFrequency);
            }

            s++;
        }
        /* Clear the memory */
        FreeAlertData(al_data);
    }
}

/* Format Field for output */
int field_add_string(char *dest, size_t size, const char *format, const char *value )
{
    char buffer[OS_SIZE_2048];
    int len = 0;
    int dest_sz = size - strlen(dest);

    /* Not enough room in the buffer? */
    if (dest_sz <= 0 ) {
        return -1;
    }

    if (value != NULL &&
            (
                ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
                ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
                ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
            )
       ) {
        len = snprintf(buffer, sizeof(buffer) - dest_sz - 1, format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}

/* Add a field, but truncate if too long */
int field_add_truncated(char *dest, size_t size, const char *format, const char *value, int fmt_size )
{
    char buffer[OS_SIZE_2048];

    int available_sz = size - strlen(dest);
    int total_sz = strlen(value) + strlen(format) - fmt_size;
    int field_sz = available_sz - strlen(format) + fmt_size;

    int len = 0;
    char trailer[] = "...";
    char *truncated = NULL;

    /* Not enough room in the buffer? */
    if (available_sz <= 0 ) {
        return -1;
    }

    if (
        ((value[0] != '(') && (value[1] != 'n') && (value[2] != 'o')) ||
        ((value[0] != '(') && (value[1] != 'u') && (value[2] != 'n')) ||
        ((value[0] != 'u') && (value[1] != 'n') && (value[4] != 'k'))
       ) {

        if ( (truncated = (char *) malloc(field_sz + 1)) != NULL ) {
            if ( total_sz > available_sz ) {
                /* Truncate and add a trailer */
                os_substr(truncated, value, 0, field_sz - strlen(trailer));
                strcat(truncated, trailer);
            } else {
                strncpy(truncated, value, field_sz);
            }

            len = snprintf(buffer, available_sz, format, truncated);
            strncat(dest, buffer, available_sz);
        } else {
            /* Memory Error */
            len = -3;
        }
    }
    /* Free the temporary pointer */
    free(truncated);

    return len;
}

/* Handle integers in the second position */
int field_add_int(char *dest, size_t size, const char *format, const int value )
{
    char buffer[255];
    int len = 0;
    int dest_sz = size - strlen(dest);

    /* Not enough room in the buffer? */
    if (dest_sz <= 0 ) {
        return -1;
    }

    if ( value > 0 ) {
        len = snprintf(buffer, sizeof(buffer), format, value);
        strncat(dest, buffer, dest_sz);
    }

    return len;
}

