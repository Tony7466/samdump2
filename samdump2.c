/*  Samdump2
    Dump nt/lanman password hashes from a sam hive with Syskey enabled
    
    Thank to Dmitry Andrianov for the program name ^_^
    
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
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
   
    This program is released under the GPL with the additional exemption 
    that compiling, linking, and/or using OpenSSL is allowed.

    Copyright (C) 2004-2006 Nicola Cuomo <ncuomo@studenti.unina.it>
    Improvments and some bugs fixes by Objectif Securité
    <http://www.objectif-securite.ch>
*/

#include <stdio.h>
#include <stdlib.h>
#include <openssl/rc4.h>
#include <openssl/md5.h>
#include <openssl/des.h>
#include "hive.h"

#ifdef BYTE_ORDER
#if BYTE_ORDER == LITTLE_ENDIAN
#elif BYTE_ORDER == BIG_ENDIAN
#include <byteswap.h>
#else
#warning "Doesn't define a standard ENDIAN type"
#endif
#else
#warning "Doesn't define BYTE_ORDER"
#endif


/* Cut&Paste from pwdump source code */

/*
* Convert a 7 byte array into an 8 byte des key with odd parity.
*/

void str_to_key(unsigned char *str,unsigned char *key)
{
	// void des_set_odd_parity(des_cblock *);
	int i;

	key[0] = str[0]>>1;
	key[1] = ((str[0]&0x01)<<6) | (str[1]>>2);
	key[2] = ((str[1]&0x03)<<5) | (str[2]>>3);
	key[3] = ((str[2]&0x07)<<4) | (str[3]>>4);
	key[4] = ((str[3]&0x0F)<<3) | (str[4]>>5);
	key[5] = ((str[4]&0x1F)<<2) | (str[5]>>6);
	key[6] = ((str[5]&0x3F)<<1) | (str[6]>>7);
	key[7] = str[6]&0x7F;
	for (i=0;i<8;i++) {
		key[i] = (key[i]<<1);
	}
	des_set_odd_parity((des_cblock *)key);
}

/*
* Function to convert the RID to the first decrypt key.
*/

void sid_to_key1(unsigned long sid,unsigned char deskey[8])
{
	unsigned char s[7];

	s[0] = (unsigned char)(sid & 0xFF);
	s[1] = (unsigned char)((sid>>8) & 0xFF);
	s[2] = (unsigned char)((sid>>16) & 0xFF);
	s[3] = (unsigned char)((sid>>24) & 0xFF);
	s[4] = s[0];
	s[5] = s[1];
	s[6] = s[2];

	str_to_key(s,deskey);
}

/*
* Function to convert the RID to the second decrypt key.
*/

void sid_to_key2(unsigned long sid,unsigned char deskey[8])
{
	unsigned char s[7];

	s[0] = (unsigned char)((sid>>24) & 0xFF);
	s[1] = (unsigned char)(sid & 0xFF);
	s[2] = (unsigned char)((sid>>8) & 0xFF);
	s[3] = (unsigned char)((sid>>16) & 0xFF);
	s[4] = s[0];
	s[5] = s[1];
	s[6] = s[2];

	str_to_key(s,deskey);
}

//---

int main( int argc, char **argv ) {
  FILE *f;
  unsigned char bootkey[] = { 0x15, 0xbd, 0x18, 0x82, 0xfa, 0x6e, 0xf7, 0xe3, 0x87, 0x90, 0x67, 0x62, 0xd3, 0xfd, 0x5b, 0x03 };
  
  /* const */
  char *regaccountkey, *reguserskey;
  unsigned char aqwerty[] = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%";
  unsigned char anum[] = "0123456789012345678901234567890123456789";
  unsigned char antpassword[] = "NTPASSWORD";
  unsigned char almpassword[] = "LMPASSWORD";

  char *root_key;

  /* hive */
  struct hive h;
  nk_hdr *n = NULL;
  
  /* hive buffer */
  unsigned char *b = NULL;
  int blen;   
  unsigned char regkeyname[50];
  int regkeynamelen;
  char  *keyname;
  
  /* md5 contex, hash, rc4 key, hashed bootkey */
  MD5_CTX md5c;
  unsigned char md5hash[0x10];
  RC4_KEY rc4k;
  unsigned char hbootkey[0x20];
  
  /* Des */
  des_key_schedule ks1, ks2;
  des_cblock deskey1, deskey2;
  
  int i, j, z;
  
  char *username;
  int rid;
  int usernameoffset, usernamelen;
  int hashesoffset;
  
  unsigned char obfkey[0x10];
  unsigned char fb[0x10];
  
  fprintf(stderr, "samdump2 1.1.0 by Objectif Securite\nhttp://www.objectif-securite.ch\noriginal author: ncuomo@studenti.unina.it\n\n" );
  
  if( argc != 3 ) {
    printf( "Usage:\nsamdump2 samhive keyfile\n" );
    return -1;
  }
  
  /* Open bootkey file */
  if( ( f = fopen( argv[2], "rb" ) ) != NULL ) {
    fread( &bootkey, 1, 16, f );
    fclose( f );
  }
  else {
    fprintf( stderr, "Error reading from %s\n", argv[2] );
    return -1;
  }
  
  /* Initialize registry access function */
  _InitHive( &h );
  
  /* Open sam hive */
  if( _RegOpenHive( argv[1], &h ) ) {
    fprintf( stderr, "Error opening sam hive or not valid file(\"%s\")\n", argv[1] );
    return -1;
  }
  
  /* Get Root key name 
     SAM for 2k/XP,
     CMI-CreateHive{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx} for Vista */
  if( _RegGetRootKey( &h, &root_key)) {
    fprintf( stderr, "Error reading hive root key\n");
    return -1;
  }
  fprintf(stderr, "Root Key : %s\n", root_key);

  regaccountkey = (char *) malloc(strlen(root_key)+30);
  reguserskey = (char *) malloc(strlen(root_key)+30);

  sprintf(regaccountkey, "%s\\SAM\\Domains\\Account", root_key);
  sprintf(reguserskey, "%s\\SAM\\Domains\\Account\\Users", root_key);

  n = (nk_hdr*) malloc(sizeof(nk_hdr));

  /* Open SAM\\SAM\\Domains\\Account key*/
  if( _RegOpenKey( &h, regaccountkey, &n ) ) {
    _RegCloseHive( &h );
    fprintf( stderr, "%s key!\n", regaccountkey );
    return -1;
  }
  
  if( _RegQueryValue( &h, "F", n, &b, &blen ) ) {       
    _RegCloseHive( &h );
    fprintf( stderr, "No F!\n" );
    return -1;
  }
  
  /* hash the bootkey */
  MD5_Init( &md5c );
  MD5_Update( &md5c, &b[0x70], 0x10 );
  MD5_Update( &md5c, aqwerty, 0x2f );
  MD5_Update( &md5c, bootkey, 0x10 );
  MD5_Update( &md5c, anum, 0x29 );
  MD5_Final( md5hash, &md5c );
  RC4_set_key( &rc4k, 0x10, md5hash );
  RC4( &rc4k, 0x20, &b[0x80], hbootkey );
  
  j = 0;
  
  /* Enumerate user */
  while( j != -1 ) {
    /* Open  SAM\\SAM\\Domains\\Account\\Users */
    if( _RegOpenKey( &h, reguserskey, &n ) ) {
      _RegCloseHive( &h );
      fprintf( stderr, "No Users key!\n" );
      return -1;
    }
    
    regkeynamelen = sizeof( regkeyname );
    
    j = _RegEnumKey( &h, n, j, (char*)regkeyname, &regkeynamelen );

#if DEBUG
    printf("******************** %d ********************\n", j);
#endif
    
    /* Skip Names key */
    if( !memcmp( regkeyname, "Names", regkeynamelen ) )
      continue;
    
    keyname = (char*) malloc( strlen( reguserskey ) + regkeynamelen + 2 );
    
    /* Open SAM\\SAM\\Domains\\Account\\Users\\userrid */
    strcpy( keyname, reguserskey );
    strcat( keyname, "\\" ) ;
    strcat( keyname, (char*)regkeyname ) ;
    
    if( _RegOpenKey( &h, keyname, &n ) ) {
      _RegCloseHive( &h );
      
      fprintf( stderr, "Asd -_- _RegEnumKey fail!\n" );
      return -1;
    }
    
    if( _RegQueryValue( &h, "V", n, &b, &blen ) ) {
      _RegCloseHive( &h );
      
      fprintf( stderr, "No V value!\n" );
      return -1;
    }
    
    /* rid */
    rid = strtoul( (char*)regkeyname, NULL, 16 );
    
    /* get the username */
    /* 0x10 username size 0xc username offset */
#if BYTE_ORDER == LITTLE_ENDIAN
    usernamelen = *(int*)(b + 0x10) >> 1;
#elif BYTE_ORDER == BIG_ENDIAN
    usernamelen = __bswap_32(*(int*)(b + 0x10) >> 1);
#endif 
    usernameoffset = b[0xc] + 0xcc;
#ifdef DEBUG 
    printf("\nusername len=%d, off=%x\n", usernamelen, usernameoffset);
#endif
    
    username = (char *) malloc(  usernamelen + 1 );

    // Quick hack for unicode -> ascii translation
    for( z = 0; z < usernamelen; z++)
      username[z] = b[usernameoffset + z*2];
    
    username[ usernamelen ] = 0;
#if BYTE_ORDER == LITTLE_ENDIAN
    hashesoffset = *(int *)(b + 0x9c ) + 0xcc;
#elif BYTE_ORDER == BIG_ENDIAN
    hashesoffset = __bswap_32(*(int *)(b + 0x9c )) + 0xcc;
#endif
#ifdef DEBUG 
    printf("hashoffset = %x, blen = %x\n", hashesoffset, blen);
#endif
    
    if( hashesoffset + 0x28 < blen ) {
#ifdef DEBUG
      printf("\n");
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", b[hashesoffset+4+i] );
      
      printf("\n");
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", b[hashesoffset+8+0x10+i] );
      printf("\n");
#endif
      /* Print the user hash */
      printf( "%s:%d:", username, rid );
      
      /* LANMAN */
      /* hash the hbootkey and decode lanman password hashes */
      MD5_Init( &md5c );
      MD5_Update( &md5c, hbootkey, 0x10 );
#if BYTE_ORDER == LITTLE_ENDIAN
      MD5_Update( &md5c, &rid, 0x4 );
#elif BYTE_ORDER == BIG_ENDIAN
      rid = __bswap_32(rid);
      MD5_Update( &md5c, &rid, 0x4 );
      rid = __bswap_32(rid);
#endif
      MD5_Update( &md5c, almpassword, 0xb );
      MD5_Final( md5hash, &md5c );        
      
      RC4_set_key( &rc4k, 0x10, md5hash );
      RC4( &rc4k, 0x10, &b[ hashesoffset + 4 ], obfkey );
#ifdef DEBUG
      printf("\nobfkey: ");
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", (unsigned char)obfkey[i] );
      printf("\n");
#endif
      
      /* From Pwdump */
      
      /* Get the two decrpt keys. */
      sid_to_key1(rid,(unsigned char *)deskey1);
      des_set_key_checked((des_cblock *)deskey1,ks1);
      sid_to_key2(rid,(unsigned char *)deskey2);
      des_set_key_unchecked((des_cblock *)deskey2,ks2);
      
      /* Decrypt the lanman password hash as two 8 byte blocks. */
      des_ecb_encrypt((des_cblock *)obfkey,
		      (des_cblock *)fb, ks1, DES_DECRYPT);
      des_ecb_encrypt((des_cblock *)(obfkey + 8),
		      (des_cblock *)&fb[8], ks2, DES_DECRYPT);
      
      
      
      // sf25( obfkey, (int*)&rid, fb );
      
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", fb[i] );
      
      printf( ":" );
      
      /* NT */
      /* hash the hbootkey and decode the nt password hashes */
      MD5_Init( &md5c );
      MD5_Update( &md5c, hbootkey, 0x10 );
#if BYTE_ORDER == LITTLE_ENDIAN
      MD5_Update( &md5c, &rid, 0x4 );
#elif BYTE_ORDER == BIG_ENDIAN
      rid = __bswap_32(rid);
      MD5_Update( &md5c, &rid, 0x4 );
      rid = __bswap_32(rid);
#endif
      MD5_Update( &md5c, antpassword, 0xb );
      MD5_Final( md5hash, &md5c );        
      
      RC4_set_key( &rc4k, 0x10, md5hash );
      RC4( &rc4k, 0x10, &b[ hashesoffset + 0x10 + 8], obfkey );
      
      /* Decrypt the NT md4 password hash as two 8 byte blocks. */
      des_ecb_encrypt((des_cblock *)obfkey,
		      (des_cblock *)fb, ks1, DES_DECRYPT);
      des_ecb_encrypt((des_cblock *)(obfkey + 8),
		      (des_cblock *)&fb[8], ks2, DES_DECRYPT);
      
      /* sf27 wrap to sf25 */
      //sf27( obfkey, (int*)&rid, fb );
      
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", fb[i] );
      
      printf( ":::\n" );
    }
    else if( hashesoffset + 0x14 < blen ) {
#ifdef DEBUG
      printf("\n");
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", b[hashesoffset+8+i] );
      printf("\n");
#endif
      /* Print the user hash */
      printf( "%s:%d:", username, rid );
      
      printf( "aad3b435b51404eeaad3b435b51404ee:" );
      
      /* NT */
      /* hash the hbootkey and decode the nt password hashes */
      MD5_Init( &md5c );
      MD5_Update( &md5c, hbootkey, 0x10 );
#if BYTE_ORDER == LITTLE_ENDIAN
      MD5_Update( &md5c, &rid, 0x4 );
#elif BYTE_ORDER == BIG_ENDIAN
      rid = __bswap_32(rid);
      MD5_Update( &md5c, &rid, 0x4 );
      rid = __bswap_32(rid);
#endif
      MD5_Update( &md5c, antpassword, 0xb );
      MD5_Final( md5hash, &md5c );        
      
      RC4_set_key( &rc4k, 0x10, md5hash );
      RC4( &rc4k, 0x10, &b[ hashesoffset + 8], obfkey );
      
      /* Get the two decrpt keys. */
      sid_to_key1(rid,(unsigned char *)deskey1);
      des_set_key((des_cblock *)deskey1,ks1);
      sid_to_key2(rid,(unsigned char *)deskey2);
      des_set_key((des_cblock *)deskey2,ks2);
      
      /* Decrypt the NT md4 password hash as two 8 byte blocks. */
      des_ecb_encrypt((des_cblock *)obfkey,
		      (des_cblock *)fb, ks1, DES_DECRYPT);
      des_ecb_encrypt((des_cblock *)(obfkey + 8),
		      (des_cblock *)&fb[8], ks2, DES_DECRYPT);
      
      /* sf27 wrap to sf25 */
      //sf27( obfkey, (int*)&rid, fb );
      
      for( i = 0; i < 0x10; i++ )
	printf( "%.2x", fb[i] );
      
      printf( ":::\n" );
    }
    
    else {
      /* Print the user hash */
      fprintf(stderr, "No password for %s\n", username);
      printf("%s:%d:", username, rid );
      
      printf("aad3b435b51404eeaad3b435b51404ee:");
      printf("31d6cfe0d16ae931b73c59d7e0c089c0");
      printf(":::\n");
    }
    
    free( username );
    free( keyname );
  }
  
  _RegCloseHive( &h );
  free(n);
  free(b);
  
  return 0;
}
