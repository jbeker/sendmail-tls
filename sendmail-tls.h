/*
	sendmail-tls.h

	TLS Wrapper for Sendmail (and other MTAs).
	Copyright (C) 1999  3-G International
	
	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.
	
	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.
	
	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

	Maintainer: Jeremy Beker <jbeker@3gi.com>

	$Id: sendmail-tls.h,v 2.2 2000/05/28 18:23:49 gothmog Exp $
	
*/

#include "config.h" // autoconf stuff

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <syslog.h>
#include <unistd.h>

#ifdef HAVE_LIBWRAP
#include <tcpd.h>
#endif

#include <pwd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifdef HAVE_POLL
#include <sys/poll.h>
#endif

#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>


// Defines

#define BUFLEN 4096 // common size for all buffers.
#define DETECT_TIMEOUT 75 // how long to wait for data during MS/RFC detection in ms
#define TIMEOUT_SEC 60 
#define TEMP_RSA_BITLEN 512

#define EHLO_TAG "EHLO"
#define HELO_TAG "HELO"
#define QUIT_TAG "QUIT"
#define TLS_TAG "STARTTLS"

#define EHLO_RESP_SIMPLE "250 "
#define EHLO_RESP_COMP "250-"

#define FAUX_HELO_RESP "250 Welcome\n"
#define STARTTLS_SIMPLE "250 STARTTLS\n"

#define ACCEPT_TLS "220 Go ahead\n"

#define E_SERVICE_UNAVAIL "421 Service not available (must use EHLO)\n"
#define E_MUST_STARTTLS "530 Must issue a STARTTLS command first\n"

#define         ERROR -1
#define		WAIT_EHLO 0
#define		GOT_EHLO 1
#define         WAIT_FOR_STARTTLS 2
#define         MOVE_TO_TLS 10
#define         PASS_DATA 11
#define         DONE 20



#define         CONN_RFC2487 1  // Netscape Messenger
#define         CONN_MS 2       // Microsoft Outlook


#define         OPT_SSL2 "ssl2"
#define         OPT_SSL3 "ssl3"
#define         OPT_TLS1 "tls1"


// Prototypes

void parse_args(int argc,char** argv);
int checkConnectionType(int fdClient);
int checkConnection(int fdClient);
int runPrelude(int fdClient, int fdMTA);
SSL* init_TLS(int fdClient);
int runSession(SSL* ssl, int fdMTA,int snarfEHLO);
int GetProcFD(char* pService,char** pArgs);
int init_context();
void print_help();
void print_license();
void openssl_info_callback(SSL* ssl,int state,int ret);
RSA* openssl_tmp_rsa_callback(SSL* ssl,int export,int keylength);

// Globals


SSL_CTX*         ctx;
static char      AppVersion[] = "sendmail-tls 0.23";
static char      AppIdent[] = "sendmail-tls";
static char      AppContext[] = "sendmail-tls SID";
char**           ppMTAArgs = NULL;
char*            pCertKeyFile = NULL;
int              nProtocolLevel = SSL2_VERSION;
char*            pServiceName = NULL;
char*            pRunAsName = NULL;
struct passwd*   pRunAsUser = NULL;
int              allow_severity=LOG_NOTICE; // for libwrap
int              deny_severity=LOG_WARNING; // for libwrap

