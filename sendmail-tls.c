/*
	sendmail-tls.c 

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

	$Id: sendmail-tls.c,v 2.2 2000/05/28 18:23:49 gothmog Exp $

*/

#include "sendmail-tls.h"

int main (int argc, char** argv)
{
  int conntype;
  int MTA;
  SSL* ssl;

  openlog(AppIdent,LOG_PID|LOG_NDELAY,LOG_MAIL);
  syslog(LOG_DEBUG,"------------------------");
  syslog(LOG_DEBUG,"Starting sendmail-tls");
  
  parse_args(argc,argv);

  if (init_context()==-1)
    {
      exit(1);
    }
 
  MTA = GetProcFD(ppMTAArgs[0],ppMTAArgs);

  if (MTA==-1)
    {
      exit(1);
    }

  // ------------------------------------------------------
  // We don't need root below this point

  if (geteuid()==0)
    {
      if (pRunAsUser !=NULL)
	{
	  seteuid(pRunAsUser->pw_uid);
	  setegid(pRunAsUser->pw_gid);
	}
      else
	{
	  syslog(LOG_CRIT,"Error in setting EUID, bailing");
	  close(MTA);
	  exit(1);
	}
    }

  if (checkConnection(STDIN_FILENO) == -1)
    {
      close(MTA);
      exit(-1);
    }

  conntype = checkConnectionType(STDIN_FILENO);

  if (conntype == CONN_MS || runPrelude(STDIN_FILENO,MTA)==1)
    {
      ssl = init_TLS(STDIN_FILENO);
      if (ssl !=NULL)
	{
	  runSession(ssl,MTA,conntype==CONN_RFC2487?1:0);
	  SSL_free(ssl);
	}
    }


  SSL_CTX_free(ctx);
  close(MTA);
  
  syslog(LOG_DEBUG,"Exiting sendmail-tls");
  syslog(LOG_DEBUG,"------------------------"); 

  closelog();
  
  return 0;
}

void parse_args(int argc,char* argv[])
{
  extern char* optarg;
  extern int optind,opterr,optopt;
  int argument;

  opterr = 0;
  pCertKeyFile = NULL;

  pServiceName = argv[0];

  while( ( argument = getopt(argc,argv,"u:p:l:VhL"))!= EOF)
    {
      switch(argument)
	{
	case 'p':
	  pCertKeyFile = optarg;
	  syslog(LOG_DEBUG, "Cert/Key file: %s",pCertKeyFile);
	  break;
	  
	case 'u':

	  if (geteuid() == 0)
	    {
	      pRunAsName = optarg;
	      pRunAsUser = getpwnam(pRunAsName);
	      
	      if (pRunAsUser==NULL)
		{
		  syslog(LOG_CRIT,"Invalid user to run as");
		  exit(1);
		}
	      
	      if(pRunAsUser->pw_uid == 0)
		{
		  syslog(LOG_CRIT,"Can't run as root user");
		  exit(1);
		}
	    }
	  else
	    {
	      syslog(LOG_CRIT,"Can't use '-u' if not root");
	      exit(1);
	    }
	  break;

	case 'l':
	  if(strncasecmp(optarg,OPT_SSL2,strlen(OPT_SSL2))==0)
	    {
	      syslog(LOG_DEBUG,"Minimum Protocol set to SSLv2");
	      nProtocolLevel = SSL2_VERSION;
	    }
	  else if(strncasecmp(optarg,OPT_SSL3,strlen(OPT_SSL3))==0)
	    {
	      syslog(LOG_DEBUG,"Minimum Protocol set to SSLv3");
	      nProtocolLevel = SSL3_VERSION;
	    }
	  else if(strncasecmp(optarg,OPT_TLS1,strlen(OPT_TLS1))==0)
	    {
	      syslog(LOG_DEBUG,"Minimum Protocol set to TLSv1");
	      nProtocolLevel = TLS1_VERSION;
	    }
	  else
	    {
	      syslog(LOG_ERR,"Invalid protocol argument: %s, defaulting to SSL2",optarg);
	      nProtocolLevel = SSL2_VERSION;
	    }
	  break;

	case 'V':
	  fprintf(stderr,"%s\n",AppVersion);
	  exit(0);
	  break;

	case 'h':
	  print_help();
	  exit(0);

	case 'L':
	  print_license();
	  exit(0);

	case '?':
	  syslog(LOG_DEBUG, "Unknown option: %c",optopt);
	  print_help();
	  exit(1);
	  break;
	}
    }

  ppMTAArgs = &argv[optind];

  syslog(LOG_DEBUG,"MTA name: %s",ppMTAArgs[0]);

  if (pCertKeyFile == NULL)
    {
      syslog(LOG_CRIT,"A certificate/keyfile must be specified, exiting");
      exit(1);
    }

  if (pRunAsUser==NULL && geteuid()==0)
    {
      syslog(LOG_CRIT,"Must specify user to run as if executing as root, use '-u'");
      exit(1);
    }

  return;
}

void print_help()
{
  fprintf(stderr,"%s\n",AppVersion);
  fprintf(stderr,"Usage: %s -p <pemfile> [-l (ssl2|ssl3|tls1)] [-u <userid>]-- mta [mta options]\n",AppIdent);
  fprintf(stderr,"Usage: %s -L\n",AppIdent);
  fprintf(stderr,"Usage: %s -V\n",AppIdent);
  fprintf(stderr,"Usage: %s -h\n",AppIdent);
  return;
}

void print_license()
{
  fprintf(stderr,"%s\n\n",AppVersion);
  	
  fprintf(stderr,"TLS Wrapper for Sendmail (and other MTAs).\n");
  fprintf(stderr,"Copyright (C) 1999  3-G International\n\n");
  
  fprintf(stderr,"This program is free software; you can redistribute it and/or\n");
  fprintf(stderr,"modify it under the terms of the GNU General Public License\n");
  fprintf(stderr,"as published by the Free Software Foundation; either version 2\n");
  fprintf(stderr,"of the License, or (at your option) any later version.\n\n");
  
  fprintf(stderr,"This program is distributed in the hope that it will be useful,\n");
  fprintf(stderr,"but WITHOUT ANY WARRANTY; without even the implied warranty of\n");
  fprintf(stderr,"MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n");
  fprintf(stderr,"GNU General Public License for more details.\n\n");
  
  fprintf(stderr,"You should have received a copy of the GNU General Public License\n");
  fprintf(stderr,"along with this program; if not, write to the Free Software\n");
  fprintf(stderr,"Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.\n\n");
  
  fprintf(stderr,"Maintainer: Jeremy Beker <jbeker@3gi.com>\n\n");
  
  return;
}

int checkConnection(int fdClient)
{
  int retval = 0;
  struct sockaddr_in remotehost;
#ifdef HAVE_LIBWRAP
  struct request_info tcpd_request;
#endif
  int size;

  size = sizeof(remotehost);
  getpeername(fdClient,&remotehost,&size);

#ifdef HAVE_LIBWRAP
  request_init(&tcpd_request,RQ_DAEMON,pServiceName,RQ_FILE,fdClient,0);
  fromhost(&tcpd_request);

  if (!hosts_access(&tcpd_request))
    {
      retval = -1;
      syslog(LOG_INFO,"Connection REFUSED from %s:%d for %s",inet_ntoa(remotehost.sin_addr),ntohs(remotehost.sin_port),pServiceName);
    }
  else
    {
      syslog(LOG_INFO,"Connection opened from %s:%d for %s",inet_ntoa(remotehost.sin_addr),ntohs(remotehost.sin_port),pServiceName);
    }
#else
  syslog(LOG_INFO,"Connection opened from %s:%d for %s",inet_ntoa(remotehost.sin_addr),ntohs(remotehost.sin_port),pServiceName);
#endif

  return retval;
}

int checkConnectionType(int fdClient)
{
  int            retval = CONN_RFC2487;
  int            err;
#ifdef HAVE_POLL
  struct pollfd polllist[1];
#else
  fd_set         fdsRead;
  int            fdno;
  struct timeval timeout;
#endif


#ifdef HAVE_POLL

  polllist[0].fd = fdClient;
  polllist[0].events = POLLIN;

  err = poll(polllist,1,DETECT_TIMEOUT);

#else
  fdno = fdClient+1;

  FD_ZERO(&fdsRead);
  FD_SET(fdClient,&fdsRead); 

  bzero(&timeout,sizeof(timeout));

  timeout.tv_usec = DETECT_TIMEOUT;

  err = select(fdno,&fdsRead,NULL,NULL,&timeout);
#endif

  if (err==0)
    {
      syslog(LOG_DEBUG, "Connection Type: CONN_RFC2487");
      retval = CONN_RFC2487;
    }
  else if (err == 1)
    {
      syslog(LOG_DEBUG, "Connection Type: CONN_MS");
      retval = CONN_MS;
    }

  return retval;
}

int runSession(SSL* ssl, int fdMTA, int snarfEHLO)
{
  int       err;
  int       lenMTA,lenClient;
  char      bufMTA[BUFLEN];
  char      bufClient[BUFLEN];
  int       fdSSL;
  int       state = PASS_DATA;

#ifdef HAVE_POLL
  struct pollfd polllist[2];
#else
  fd_set    fdsRead;
  int       fdno;
  struct timeval timeout;
#endif

  fdSSL = SSL_get_fd(ssl);

#ifdef HAVE_POLL
  polllist[0].fd = fdMTA;
  polllist[1].fd = fdSSL;

  polllist[0].events = POLLIN;
  polllist[1].events = POLLIN;
#else
  fdno = (fdSSL>fdMTA?fdSSL:fdMTA)+1;
  timeout.tv_sec = TIMEOUT_SEC;
#endif

  while (state != DONE)
    {
      lenClient=0;
      lenMTA=0;

#ifdef HAVE_POLL
      err = poll(polllist,2,TIMEOUT_SEC*1000);
#else
      FD_ZERO(&fdsRead);

      FD_SET(fdSSL,&fdsRead);
      FD_SET(fdMTA,&fdsRead);
      
      err = select(fdno,&fdsRead,NULL,NULL,&timeout);
#endif

      if (err==0)
	{
	  syslog(LOG_ERR, "Connection Timed out while waiting for data");
	  return -1;
	}

#ifdef HAVE_POLL
      if (polllist[0].revents & POLLERR)
	{
	  syslog(LOG_INFO, "Error from MTA");
	  state = DONE;
	}

      if (polllist[0].revents & POLLHUP)
	{
	  syslog(LOG_INFO, "Connection Closed by MTA");
	  state = DONE;
	}

      if (polllist[1].revents & POLLERR)
	{
	  syslog(LOG_INFO, "Error from Client");
	  state = DONE;
	}

      if (polllist[1].revents & POLLHUP)
	{
	  syslog(LOG_INFO, "Connection Closed by Client");
	  state = DONE;
	}
#endif



#ifdef HAVE_POLL
      if (polllist[1].revents & POLLIN)
#else
      if (FD_ISSET(fdSSL,&fdsRead))
#endif
	{
	  bzero(bufClient,BUFLEN);
	  lenClient = SSL_read(ssl,bufClient,BUFLEN);

	  if (lenClient <= 0)
	    {
	      syslog(LOG_INFO, "Connection Closed by Client");
	      state = DONE;
	    }
	}

#ifdef HAVE_POLL
      if (polllist[0].revents & POLLIN)
#else
       if (FD_ISSET(fdMTA,&fdsRead))
#endif
	{
	  bzero(bufMTA,BUFLEN);
	  lenMTA = recv(fdMTA,bufMTA,BUFLEN,0);

	  if (lenMTA <= 0)
	    {	      
	      syslog(LOG_INFO, "Connection Closed by MTA");
	      state = DONE;
	    }
	}
       
       // Remove stray HELO/EHLO if required
       // Basically to fix bug in Netscape's implementation of rfc2487.  
       // They send a second EHLO after initiating TLS session.

       if (snarfEHLO == 1 && lenClient>0 && (strncasecmp(EHLO_TAG,bufClient,strlen(EHLO_TAG)) == 0 ||  strncasecmp(HELO_TAG,bufClient,strlen(HELO_TAG)) == 0) )
	 {
	   syslog(LOG_WARNING, "Saw stray HELO/EHLO, ignoring");
	   bzero (bufClient,BUFLEN);
	   lenClient = 0;

	   bzero(bufMTA,BUFLEN);
	   memcpy(bufMTA,FAUX_HELO_RESP,strlen(FAUX_HELO_RESP));
	   lenMTA = strlen(FAUX_HELO_RESP);
	 }
       
       if (lenClient >0)
	 {
	   // TODO: check return val
	   send(fdMTA,bufClient,lenClient,0);
	 }
       
       if (lenMTA >0)
	 {
	   // TODO: check return val
	   SSL_write(ssl,bufMTA,lenMTA);
	 }
    }

  return 1; 
}

SSL* init_TLS(int fdClient)
{
  SSL* ssl= NULL;
  struct sockaddr_in remotehost;
  int size;
  
  ssl = SSL_new(ctx);

  

  size = sizeof(remotehost);
  getpeername(fdClient,&remotehost,&size);

  if (ssl != NULL)
    {
      unsigned long err;
      char buf[BUFLEN];

      SSL_set_fd(ssl,fdClient);
      SSL_set_accept_state(ssl);
      
      err = SSL_accept(ssl);

      // syslog(LOG_DEBUG,"SSL_accept returned: %d",err);

      SSL_set_session_id_context(ssl,AppContext,sizeof(AppContext));
     
      if (err ==-1)
	{
	  syslog(LOG_ERR,"OpenSSL Error: %s :from %s:%d",ERR_error_string(ERR_get_error(),buf),inet_ntoa(remotehost.sin_addr),ntohs(remotehost.sin_port));
	  SSL_set_shutdown(ssl,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
	  SSL_free(ssl);
	  ssl = NULL;
	}
      else
	{
	  SSL_CIPHER* cipher;
	  char* prot_level;
	  int bits;

	  syslog(LOG_DEBUG,"Shared ciphers: %s",SSL_get_shared_ciphers(ssl, buf, BUFLEN));

	  switch(ssl->session->ssl_version)
	    {
	    case SSL2_VERSION:
	      prot_level = "SSLv2";
	      break;

	    case SSL3_VERSION:                                
	      prot_level = "SSLv3";
	      break;

	    case TLS1_VERSION:
	      prot_level = "TLS1";
	      break;
	      
	    default:
	      prot_level = "Unknown";
	      break;
	    }

	  cipher  = SSL_get_current_cipher(ssl);
	  SSL_CIPHER_get_bits(cipher,&bits);

	  if (bits == 0)
	    {
	      syslog(LOG_INFO,"Secure channel not opened from %s:%d with %s, cipher %s, %d bits",inet_ntoa(remotehost.sin_addr),ntohs(remotehost.sin_port),prot_level,SSL_CIPHER_get_name(cipher),bits);
	      
	      SSL_set_shutdown(ssl,SSL_SENT_SHUTDOWN|SSL_RECEIVED_SHUTDOWN);
	      SSL_free(ssl);
	      ssl = NULL;
	    }
	  else
	    {
	      syslog(LOG_INFO,"Secure channel opened from %s:%d with %s, cipher %s, %d bits",inet_ntoa(remotehost.sin_addr),ntohs(remotehost.sin_port),prot_level,SSL_CIPHER_get_name(cipher),bits);
	    }
	}
    }
  else
    {
      syslog(LOG_ERR,"Error creating SSL object");
    }

  return ssl;
}


int runPrelude(int fdClient, int fdMTA)
{
  int       err;
  int       lenMTA,lenClient;
  char      bufMTA[BUFLEN];
  char      bufClient[BUFLEN];
  int       state = WAIT_EHLO;

#ifdef HAVE_POLL
  struct pollfd polllist[2];
#else
  fd_set    fdsRead;
  int       fdno;
  struct timeval timeout;
#endif

#ifdef HAVE_POLL
  polllist[0].fd = fdMTA;
  polllist[1].fd = fdClient;

  polllist[0].events = POLLIN;
  polllist[1].events = POLLIN;

#else
  fdno = (fdClient>fdMTA?fdClient:fdMTA)+1;
  timeout.tv_sec = TIMEOUT_SEC;
#endif

  while (state != MOVE_TO_TLS && state != ERROR)
    {

      lenClient=0;
      lenMTA=0;

#ifdef HAVE_POLL
      err = poll(polllist,2,TIMEOUT_SEC*1000);
#else
      FD_ZERO(&fdsRead);

      FD_SET(fdClient,&fdsRead);
      FD_SET(fdMTA,&fdsRead);
      
      err = select(fdno,&fdsRead,NULL,NULL,&timeout);
#endif
      
      if (err==0)
	{
	  syslog(LOG_ERR, "Connection Timed out while waiting for data");
	  return -1;
	}


#ifdef HAVE_POLL
      if (polllist[0].revents & POLLERR)
	{
	  syslog(LOG_INFO, "Error from MTA");
	  state = ERROR;
	}

      if (polllist[0].revents & POLLHUP)
	{
	  syslog(LOG_INFO, "Connection Closed by MTA");
	  state = ERROR;
	}

      if (polllist[1].revents & POLLERR)
	{
	  syslog(LOG_INFO, "Error from Client");
	  state = ERROR;
	}

      if (polllist[1].revents & POLLHUP)
	{
	  syslog(LOG_INFO, "Connection Closed by Client");
	  state = ERROR;
	}
#endif

#ifdef HAVE_POLL
      if (polllist[1].revents & POLLIN)
#else
      if (FD_ISSET(fdClient,&fdsRead))
#endif
	{
	  bzero(bufClient,BUFLEN);
	  lenClient = recv(fdClient,bufClient,BUFLEN,0);

	  if (lenClient == 0)
	    {
	      syslog(LOG_ERR, "Connection Closed by Client");
	      state = ERROR;
	    }
	}


#ifdef HAVE_POLL
      if (polllist[0].revents & POLLIN)
#else
      if (FD_ISSET(fdMTA,&fdsRead))
#endif
	{
	  bzero(bufMTA,BUFLEN);
	  lenMTA = recv(fdMTA,bufMTA,BUFLEN,0);

	  if (lenMTA == 0)
	    {	      
	      syslog(LOG_ERR, "Connection Closed by MTA");
	      state = ERROR;
	    }
	}
   
       // modify data if needed
       
       switch (state)
	 {
	   
	 case WAIT_EHLO:
	   {
	     if (lenClient>0 && strncasecmp(EHLO_TAG,bufClient,strlen(EHLO_TAG)) == 0 )
	       {
		 //syslog(LOG_DEBUG, "Saw EHLO");
		 state=GOT_EHLO;
	       }
	    else if (lenClient > 0 && strncasecmp(HELO_TAG,bufClient,strlen(HELO_TAG)) == 0)
	      {
		//syslog(LOG_DEBUG, "Saw HELO");
		// Send error (put data in buffers to terminate connects
		lenMTA = strlen(E_SERVICE_UNAVAIL);
		strncpy(bufMTA,E_SERVICE_UNAVAIL,lenMTA);
		
		lenClient = strlen(QUIT_TAG);
		strncpy(bufClient,QUIT_TAG,lenClient);
		state = ERROR;
	      }
	     break;
	   }
	   
	 case GOT_EHLO:
	   {
	    if (lenMTA > 0)
	       {
		 char* loc;
		 loc = strstr(bufMTA,EHLO_RESP_SIMPLE);
		 if (loc!=NULL)
		   {
		     //syslog(LOG_DEBUG,"Saw 250");
		     
		     // This code assumes strlen(EHLO_RESP_SIMPLE) == strlen(EHLO_RESP_COMP)
		     // this is probably not a good thing.

		     if (lenMTA + strlen(STARTTLS_SIMPLE) > BUFLEN)
		       {
			 syslog(LOG_ALERT,"Possible buffer overrun, bailing!");
		       }
		     else
		       {
			 strncpy(loc,EHLO_RESP_COMP,strlen(EHLO_RESP_COMP));
			 strncpy(&bufMTA[lenMTA],STARTTLS_SIMPLE,strlen(STARTTLS_SIMPLE));
			 lenMTA += strlen(STARTTLS_SIMPLE);
			 state = WAIT_FOR_STARTTLS;
		       }
		   }
	       }
	     break;
	   }

	 case WAIT_FOR_STARTTLS:
	   {
	     if (lenClient >0 && strncasecmp(TLS_TAG,bufClient,strlen(TLS_TAG)) == 0)
	       {
		 syslog(LOG_DEBUG,"Got STARTTLS");
		 lenMTA = strlen(ACCEPT_TLS);
		 strncpy(bufMTA,ACCEPT_TLS,lenMTA);

		 bzero(bufClient,BUFLEN);
		 lenClient = 0;
		 
		 state = MOVE_TO_TLS;
	       }
	     else if (lenClient > 0 && strncasecmp(QUIT_TAG,bufClient,strlen(QUIT_TAG)) == 0)
	       {
		 // Let it pass through.
	       }
	     else if (lenClient >0)
	       {
		 syslog(LOG_DEBUG,"Didn't get STARTTLS");
		 lenMTA = strlen(E_MUST_STARTTLS);
		 strncpy(bufMTA,E_MUST_STARTTLS,lenMTA);
		 
		 bzero(bufClient,BUFLEN);
		 lenClient = 0;
	       }
	     break;
	   }

	 case ERROR:
	   break;

	 default:
	   {
	     syslog(LOG_ALERT,"Hit default case in runPrelude. bailing!");
	     state= ERROR;
	     return -1;
	   }

	 }
       
       if (lenClient >0)
	 {
	   // TODO: check return val
	   send(fdMTA,bufClient,lenClient,0);
	 }
       
       if (lenMTA >0)
	 {	
	   // TODO: check return val
	   send(fdClient,bufMTA,lenMTA,0);
	 }
    }
  return state == ERROR?-1:1; 
}

int GetProcFD(char* pService,char** pArgs)
{
  int fd[2];
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fd))
    {
      syslog(LOG_ERR,"socketpair failed: %s",strerror(errno));
      return -1;
    }
  switch(fork()) 
    {
    case -1:
      {
	// Error
	close(fd[0]);
	close(fd[1]);
	syslog(LOG_ERR,"Error forking for MTA");
	return -1;
      }
    case  0:
      {
	// In child
	close(fd[0]);
	dup2(fd[1], STDIN_FILENO);
	dup2(fd[1], STDOUT_FILENO);
	dup2(fd[1], STDERR_FILENO);
	close(fd[1]);
	if (execv(pService, pArgs)==-1)
	{
		syslog(LOG_ERR,"Error execing MTA '%s'.  Invalid executable?",pService);
	}
	  }
    }
  // In parent
  close(fd[1]);
  return fd[0];
}
RSA* openssl_tmp_rsa_callback(SSL* ssl,int export,int keylength)
{
  syslog(LOG_DEBUG,"temp rsa callback: export = %d, keylength=%d",export,keylength);
  return RSA_generate_key(keylength,RSA_F4,NULL,NULL);;
}

void openssl_info_callback(SSL* ssl,int state,int ret)
{
  char* state_name;

  switch (state)
    {
    case SSL_CB_LOOP:
      state_name = "SSL_CB_LOOP";
      break;
    case SSL_CB_EXIT:
      state_name = "SSL_CB_EXIT";
      break;
    case SSL_CB_READ:
      state_name = "SSL_CB_READ";
      break;
    case SSL_CB_WRITE:
      state_name = "SSL_CB_WRITE";
      break;
    case SSL_CB_ALERT:
      state_name = "SSL_CB_ALERT";
      break;
    case SSL_CB_READ_ALERT:
      state_name = "SSL_CB_READ_ALERT";
      break;
    case SSL_CB_WRITE_ALERT:
      state_name = "SSL_CB_WRITE_ALERT";
      break;
    case SSL_CB_ACCEPT_LOOP:
      state_name = "SSL_CB_ACCEPT_LOOP";
      break;
    case SSL_CB_ACCEPT_EXIT:
      state_name = "SSL_CB_ACCEPT_EXIT";
      break;
    case SSL_CB_CONNECT_LOOP:
      state_name = "SSL_CB_CONNECT_LOOP";
      break;
    case SSL_CB_CONNECT_EXIT:
      state_name = "SSL_CB_CONNECT_EXIT";
      break;
    case SSL_CB_HANDSHAKE_START:
      state_name = "SSL_CB_HANDSHAKE_START";
      break;
    case SSL_CB_HANDSHAKE_DONE:
      state_name = "SSL_HANDSHAKE_DONE";
      break;

    default:
      state_name = "Unknowm";
      break;
    }

  syslog(LOG_DEBUG,"info_callback: state = %s, ret = %d",state_name,ret);
}

int init_context()
{
  int err;
  SSL_load_error_strings();
  SSLeay_add_ssl_algorithms();



  switch(nProtocolLevel)
    {
    case SSL2_VERSION:
      ctx = SSL_CTX_new(SSLv2_method());
      break;

    case SSL3_VERSION:
      ctx = SSL_CTX_new(SSLv23_method());
      SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2);
      break;

    case TLS1_VERSION:
        ctx = SSL_CTX_new(TLSv1_method());
      break;
    }
  SSL_CTX_set_options(ctx, SSL_OP_ALL);
 
  SSL_CTX_set_cipher_list(ctx,"!ADH:RC4+RSA:HIGH:MEDIUM:LOW:EXP:+SSLv2:+EXP");

  SSL_CTX_set_timeout(ctx,0);

  if (ctx == NULL)
    {
      syslog(LOG_ERR,"SSL_CTX_new failed");
      return -1;	
    }
  
  err = SSL_CTX_use_RSAPrivateKey_file(ctx, pCertKeyFile,  SSL_FILETYPE_PEM);
  if (err == -1)
    {
      syslog(LOG_ERR,"SSL_CTX_use_RSAPrivateKey_file failed");
      return -1;	
    }
  
  err = SSL_CTX_use_certificate_file(ctx, pCertKeyFile, SSL_FILETYPE_PEM);
  if (err == -1)
    {
      syslog(LOG_ERR,"SSL_CTX_use_certificate_file failed");
      return -1;
    }


  SSL_CTX_set_tmp_rsa_callback(ctx,openssl_tmp_rsa_callback);


 
  /* err = SSL_CTX_set_info_callback(ctx,openssl_info_callback);

  if (err == -1)
    {
      syslog(LOG_ERR,"SSL_CTX_set_info_callback failed");
      return -1;	
    }
  */
  return 1;
}
