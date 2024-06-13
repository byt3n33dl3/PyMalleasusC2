/*
 * version.h
 *
 *  Created on: Feb 15, 2020
 *      Author: zeus
 */

#ifndef VERSION_H_
#define VERSION_H_

#define version	 "1.3.0"
/*
* sni : use libev with single thread
*/

//#define version	 "1.2.3"
/*
* dns : add timeout
*/

//#define version	 "1.2.2"
/*
* dns: add worker
* dns: tcp pipe to server
*/

//#define version	 "1.2.1"
/*
* dns: fix segmentfault !
*/

//#define version	 "1.2"
/*
* socks: add domain support for socks
* socks: add Authentication user/pass method(RFC 1929)
*/

//#define version	 "1.1"
/*
* dns: add dns decoder packet library
*/

//#define version	 "1.0"
/*
 * args: add flag -c for load config file
 * args: add load config from file
 * args: check config file when no args uses
*/

//#define version	 "0.9"
/*
 * filter: auto reload filter
*/

//#define version	 "0.8"
/*
 * DNS : fix Statistics
 */

//#define version	 "0.7"
/*
 * args: fix in passing argument error
 * SNI : Limit client buffer to 8kb
 * Statistics : change folder
 * DNS : Move to thered from fork
 * DNS : Add statistic
 */

//#define version	 "0.6"
/*
 * DNS : installs SIGCHLD handler to die when the child exits
 * DNS : Fix bug in not exit from fork process
 */

//#define version	 "0.5"
/*
 * Socks : Fix bug in detection domain/ip
 * SNI   : add remote port for send request to this port
 * SNI   : add local port for listen to this port
 * SNI   : add bind ip
 */

//#define version	 "0.4"
/*
 * Add DNS Proxy
 * Add Config File
 * Add u & d key for input argumant
 * DNS : Add dns proxy from Socks socket
 * Socks : add domain/ip support
 */

//#define version	 "0.3"
/*
 * monitor : show usage in human readable format
 * monitor : remove 'gmtime' function
 * monitor : close connection after replay
 * monitor : Apache Bench:'Requests per second:    17830.07 [#/sec]'
 * monitor : change form none block read to thread
 */

//#define version	 "0.2"
/*
 * Add Monitor and statistic
 * reject ip connection for sni client
 */

//#define version	 "0.1"
/*
 * Init Program version :)
 */


#endif /* VERSION_H_ */
