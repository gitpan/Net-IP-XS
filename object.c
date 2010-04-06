/*
object.c - Functions for Net::IP::XS's object-oriented interface.

Copyright (C) 2010 Tom Harrison <tomhrr@cpan.org>
Original inet_pton4, inet_pton6 are Copyright (C) 2006 Free Software
Foundation.
Original interface, and the auth and ip_auth functions, are Copyright
(C) 1999-2002 RIPE NCC.

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "functions.h"

#define HV_PV_GET_OR_RETURN(name, object, str, len) \
    name = NI_hv_get_pv(object, str, len); \
    if (!name) { return 0; }

#define HV_MY_DELETE(object, str, len) \
    hv_delete((HV*) SvRV(object), str, len, G_DISCARD);

#define HV_MY_STORE_IV(object, str, len, var) \
    hv_store((HV*) SvRV(object), str, len, newSViv(var), 0);

#define HV_MY_STORE_UV(object, str, len, var) \
    hv_store((HV*) SvRV(object), str, len, newSVuv(var), 0);

#define HV_MY_STORE_PV(object, str, len, var, varlen) \
    hv_store((HV*) SvRV(object), str, len, newSVpv(var, varlen), 0);

#ifdef __cplusplus
extern "C" {
#endif

/**
 * NI_object_set_Error_Errno() - set object error number and string.
 * @ip: Net::IP::XS object.
 * @Errno: the new error number.
 * @Error: the new error string (can include printf modifiers).
 * @...: format arguments to substitute into @Error.
 */
void
NI_object_set_Error_Errno(SV *ipo, int Errno, char *Error, ...)
{
    char errtmp[512];
    va_list args;

    va_start(args, Error);
    vsnprintf(errtmp, 512, Error, args);
    errtmp[511] = '\0';

    HV_MY_STORE_PV(ipo, "error", 5, errtmp, 0);
    HV_MY_STORE_IV(ipo, "errno", 5, Errno);

    va_end(args);
}

/**
 * NI_copy_Error_Errno() - copy global error details to object.
 * @ip: Net::IP::XS object.
 */
void
NI_copy_Error_Errno(SV *ipo)
{
    HV_MY_STORE_PV(ipo, "error", 5, NI_get_Error(), 0);
    HV_MY_STORE_IV(ipo, "errno", 5, NI_get_Errno());
}

/**
 * NI_find_prefixes(): get prefix for Net::IP::XS object.
 * @ip: Net::IP::XS object.
 * @prefixes: prefix strings buffer.
 * @pcount: prefix count buffer.
 *
 * See NI_ip_range_to_prefix().
 */
int
NI_find_prefixes(SV *ipo, char **prefixes, int *pcount)
{
    const char *binip;
    const char *last_bin;
    int ipversion;
    int res;

    HV_PV_GET_OR_RETURN(binip,    ipo, "binip",    5);
    HV_PV_GET_OR_RETURN(last_bin, ipo, "last_bin", 8);
    ipversion = NI_hv_get_iv(ipo, "ipversion", 9);

    res = NI_ip_range_to_prefix(binip, last_bin,
                                ipversion, prefixes, pcount);

    if (!res || !(*pcount)) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    return 1;
}

/**
 * NI_set_ipv6_mpzs(): set GMP integers in IPv6 Net::IP::XS object.
 * @ip: Net::IP::XS object.
 *
 * Relies on 'binip' and 'last_bin' being set in the object.
 */
int
NI_set_ipv6_mpzs(SV *ipo)
{
    mpz_t *ipv6_begin;
    mpz_t *ipv6_end;
    HV *stash;
    SV *ref1;
    SV *ref2;
    SV *ipv6_begin_ref;
    SV *ipv6_end_ref;
    const char *binbuf1;
    const char *binbuf2;

    HV_PV_GET_OR_RETURN(binbuf1, ipo, "binip",    5);
    HV_PV_GET_OR_RETURN(binbuf2, ipo, "last_bin", 8);

    stash = gv_stashpv("Net::IP::XS::GN", 1);

    ipv6_begin = (mpz_t *) malloc(sizeof(mpz_t));
    if (!ipv6_begin) {
        printf("set: malloc failed!\n");
        return 0;
    }
    ipv6_end = (mpz_t *) malloc(sizeof(mpz_t));
    if (!ipv6_end) {
        printf("set: malloc failed!\n");
        return 0;
    }

    mpz_init2(*ipv6_begin,  128);
    mpz_init2(*ipv6_end,    128);

    NI_ip_bintompz(binbuf1, 128, ipv6_begin);
    NI_ip_bintompz(binbuf2, 128, ipv6_end);

    ipv6_begin_ref = newSViv(PTR2IV(ipv6_begin));
    ipv6_end_ref   = newSViv(PTR2IV(ipv6_end));

    ref1 = newRV_noinc(ipv6_begin_ref);
    ref2 = newRV_noinc(ipv6_end_ref);

    sv_bless(ref1, stash);
    sv_bless(ref2, stash);

    hv_store((HV*) SvRV(ipo), "xs_v6_ip0", 9, ref1, 0);
    hv_store((HV*) SvRV(ipo), "xs_v6_ip1", 9, ref2, 0);

    return 1;
}

/**
 * NI_set(): construct a new Net::IP::XS object.
 * @ip: Net::IP::XS object (can be initialised).
 * @version: IP address version.
 */
int
NI_set(SV* ipo, char *data, int ipversion)
{
    char buf1[MAX_IPV6_STR_LEN];
    char buf2[MAX_IPV6_STR_LEN];
    char binbuf1[IPV6_BITSTR_LEN];
    char binbuf2[IPV6_BITSTR_LEN];
    char maskbuf[IPV6_BITSTR_LEN];
    char prefixbuf[MAX_IPV6_STR_LEN];
    char *prefixes[MAX_PREFIXES];
    char *binbuf2p;
    int res;
    int cmp_res;
    int num_addrs;
    int endipversion;
    int iplen;
    int pcount;
    int prefixlen;
    int i;

    buf1[0] = '\0';
    buf2[0] = '\0';

    binbuf1[0] = '\0';
    binbuf2[0] = '\0';
    maskbuf[0] = '\0';

    num_addrs = NI_ip_normalize(data, buf1, buf2);
    if (!num_addrs) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    HV_MY_DELETE(ipo, "ipversion",  9);
    HV_MY_DELETE(ipo, "prefixlen",  9);
    HV_MY_DELETE(ipo, "binmask",    7);
    HV_MY_DELETE(ipo, "reverse_ip", 10);
    HV_MY_DELETE(ipo, "last_ip",    7);
    HV_MY_DELETE(ipo, "iptype",     6);
    HV_MY_DELETE(ipo, "binip",      5);
    HV_MY_DELETE(ipo, "error",      5);
    HV_MY_DELETE(ipo, "ip",         2);
    HV_MY_DELETE(ipo, "intformat",  9);
    HV_MY_DELETE(ipo, "mask",       4);
    HV_MY_DELETE(ipo, "last_bin",   8);
    HV_MY_DELETE(ipo, "last_int",   8);
    HV_MY_DELETE(ipo, "prefix",     6);
    HV_MY_DELETE(ipo, "is_prefix",  9);

    if (!ipversion) {
        ipversion = NI_ip_get_version(buf1);
        if (!ipversion) {
            return 0;
        }
    }

    iplen = NI_iplengths(ipversion);
    if (!iplen) {
        return 0;
    }

    HV_MY_STORE_IV(ipo, "ipversion", 9, ipversion);
    HV_MY_STORE_PV(ipo, "ip",        2, buf1, 0);

    binbuf1[iplen] = '\0';
    res = NI_ip_iptobin(buf1, ipversion, binbuf1);
    if (!res) {
        return 0;
    }

    HV_MY_STORE_PV(ipo, "binip",     5, binbuf1, iplen);
    HV_MY_STORE_IV(ipo, "is_prefix", 9, 0);

    if (num_addrs == 1) {
        HV_MY_STORE_PV(ipo, "last_ip",  7, buf1, 0);
        HV_MY_STORE_PV(ipo, "last_bin", 8, binbuf1, iplen);
        binbuf2p = binbuf1;
    } else {
        endipversion = NI_ip_get_version(buf2);
        if (!endipversion) {
            return 0;
        }
        if (endipversion != ipversion) {
            NI_set_Error_Errno(201, "Begin and End addresses have "
                                    "different IP versions - %s - %s",
                                   buf1, buf2);
            NI_copy_Error_Errno(ipo);
            return 0;
        }

        binbuf2[iplen] = '\0';
        res = NI_ip_iptobin(buf2, ipversion, binbuf2);
        if (!res) {
            return 0;
        }

        HV_MY_STORE_PV(ipo, "last_ip",  7, buf2, 0);
        HV_MY_STORE_PV(ipo, "last_bin", 8, binbuf2, iplen);

        res = NI_ip_bincomp(binbuf1, "le", binbuf2, &cmp_res);
        if (!res) {
            return 0;
        }
        if (!cmp_res) {
            NI_set_Error_Errno(202, "Begin address is greater than End "
                                    "address %s - %s",
                                   buf1, buf2);
            NI_copy_Error_Errno(ipo);
            return 0;
        }
        binbuf2p = binbuf2;
    }

    pcount = 0;
    res = NI_find_prefixes(ipo, prefixes, &pcount);
    if (!res) {
        return 0;
    }

    if (pcount == 1) {
        char *prefix = prefixes[0];

        res = NI_ip_splitprefix(prefix, prefixbuf, &prefixlen);
        if (!res) {
            free(prefix);
            return 0;
        }

        NI_ip_get_mask(prefixlen, ipversion, maskbuf);

        res = NI_ip_check_prefix(binbuf1, prefixlen, ipversion);
        if (!res) {
            free(prefix);
            NI_copy_Error_Errno(ipo);
            return 0;
        }

        HV_MY_STORE_IV(ipo, "prefixlen", 9, prefixlen);
        HV_MY_STORE_IV(ipo, "is_prefix", 9, 1);
        HV_MY_STORE_PV(ipo, "binmask",   7, maskbuf, iplen);
    }

    for (i = 0; i < pcount; ++i) {
        free(prefixes[i]);
    }

    if (ipversion == 4) {
        HV_MY_STORE_UV(ipo, "xs_v4_ip0", 9, NI_bintoint(binbuf1,  32));
        HV_MY_STORE_UV(ipo, "xs_v4_ip1", 9, NI_bintoint(binbuf2p, 32));
    } else {
        res = NI_set_ipv6_mpzs(ipo);
        if (!res) {
            return res;
        }
    }

    return 1;
}

/**
 * NI_get_begin_mpz(): get beginning address of IPv6 object as GMP integer.
 * @ip: Net::IP::XS object.
 * @begin: reference to GMP integer.
 *
 * On success, @begin will point to the beginning address stored in
 * the IPv6 object.
 */
int
NI_get_begin_mpz(SV *ipo, mpz_t **begin)
{
    SV **ref;

    ref = hv_fetch((HV*) SvRV(ipo), "xs_v6_ip0", 9, 0);
    if (!ref || !(*ref) || !SvROK(*ref) || !sv_isa(*ref, "Net::IP::XS::GN")) {
        return 0;
    }
    *begin = INT2PTR(mpz_t*, SvUV(SvRV(*ref)));

    return 1;
}

/**
 * NI_get_end_mpz(): get beginning address of IPv6 object as GMP integer.
 * @ip: Net::IP::XS object.
 * @end: reference to GMP integer.
 *
 * On success, @end will point to the last address stored in the
 * IPv6 object.
 */
int
NI_get_end_mpz(SV *ipo, mpz_t **end)
{
    SV **ref;

    ref = hv_fetch((HV*) SvRV(ipo), "xs_v6_ip1", 9, 0);
    if (!ref || !(*ref) || !SvROK(*ref) || !sv_isa(*ref, "Net::IP::XS::GN")) {
        return 0;
    }
    *end = INT2PTR(mpz_t*, SvUV(SvRV(*ref)));

    return 1;
}

/**
 * NI_get_mpzs(): get begin-end addresses of IPv6 object as GMP integers.
 * @ip: Net::IP::XS object.
 * @begin: reference to GMP integer.
 * @end: reference to GMP integer.
 *
 * See NI_get_begin_mpz() and NI_get_end_mpz().
 */
int
NI_get_mpzs(SV *ipo, mpz_t **begin, mpz_t **end)
{
    return    NI_get_begin_mpz(ipo, begin)
           && NI_get_end_mpz(ipo, end);
}

/**
 * NI_short(): get the short format of the first IP address in the object.
 * @ip: Net::IP::XS object.
 * @buf: buffer for short format string.
 *
 * @buf will be null-terminated on success.
 */
int
NI_short(SV *ipo, char *buf)
{
    int version;
    int prefixlen;
    int res;
    const char *ipstr;
    
    version = NI_hv_get_iv(ipo, "ipversion", 9);
    ipstr   = NI_hv_get_pv(ipo, "ip", 2);
    if (!ipstr) {
        ipstr = "";
    }

    if (version == 6) {
        res = NI_ip_compress_address(ipstr, 6, buf);
    } else {
        prefixlen = NI_hv_get_iv(ipo, "prefixlen", 9);
        res = NI_ip_compress_v4_prefix(ipstr, prefixlen, buf, 40);
    }

    if (!res) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    return 1;
}

/**
 * NI_last_ip(): get last IP address of a range as a string.
 * @ipo: Net::IP::XS object.
 * @buf: IP address buffer.
 * @maxlen: maximum capacity of buffer.
 */
int
NI_last_ip(SV *ipo, char *buf, int maxlen)
{
    const char *last_ip;
    const char *last_bin;
    int version;
    int res;

    if ((last_ip = NI_hv_get_pv(ipo, "last_ip", 7))) {
        snprintf(buf, maxlen, "%s", last_ip);
        return 1;
    }

    last_bin = NI_hv_get_pv(ipo, "last_bin", 8);
    if (!last_bin) {
        last_bin = "";
    }

    version = NI_hv_get_iv(ipo, "ipversion", 9);

    res = NI_ip_bintoip(last_bin, version, buf);
    if (!res) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    HV_MY_STORE_PV(ipo, "last_ip", 7, buf, 0);

    return 1;
}

/**
 * NI_print(): get the IP address/range in string format.
 * @ip: Net::IP::XS object.
 * @buf: buffer for the string.
 *
 * If the object represents a single prefix, the buffer will get the
 * short format of the first address (as per NI_short()), plus a '/',
 * plus the prefix length. Otherwise, it will get the first address,
 * plus " - ", plus the last address (neither in short (compressed)
 * format).
 */
int
NI_print(SV *ipo, char *buf, int maxlen)
{
    int is_prefix;
    int prefixlen;
    const char *first_ip;
    const char *second_ip;
    int res;
    char mybuf[MAX_IPV6_STR_LEN];

    is_prefix = NI_hv_get_iv(ipo, "is_prefix", 9);

    if (is_prefix) {
        res = NI_short(ipo, mybuf);
        if (!res) {
            return 0;
        }
        prefixlen = NI_hv_get_iv(ipo, "prefixlen", 9);
        snprintf(buf, maxlen, "%s/%d", mybuf, prefixlen);
    } else {
        first_ip = NI_hv_get_pv(ipo, "ip", 2);
        if (!first_ip) {
            return 0;
        }

        NI_last_ip(ipo, mybuf, MAX_IPV6_STR_LEN);
        second_ip = NI_hv_get_pv(ipo, "last_ip", 7);
        if (!second_ip) {
            return 0;
        }

        snprintf(buf, maxlen, "%s - %s", first_ip, second_ip);
    }

    return 1;
}

/**
 * NI_size_str_ipv4(): get size of IPv4 object as a string.
 * @ip: Net::IP::XS object.
 * @buf: size buffer.
 */
int
NI_size_str_ipv4(SV *ipo, char *buf)
{
    unsigned long begin;
    unsigned long end;

    begin  = NI_hv_get_uv(ipo, "xs_v4_ip0", 9);
    end    = NI_hv_get_uv(ipo, "xs_v4_ip1", 9);

    if ((begin == 0) && (end = 0xFFFFFFFF)) {
        sprintf(buf, "4294967296");
    } else {
        sprintf(buf, "%lu", end - begin + 1);
    }

    return 1;
}

/**
 * NI_size_str_ipv6(): get size of IPv6 object as a string.
 * @ip: Net::IP::XS object.
 * @buf: size buffer.
 */
int
NI_size_str_ipv6(SV *ipo, char *buf)
{
    mpz_t *begin;
    mpz_t *end;
    mpz_t end_copy;
    int res;

    res = NI_get_mpzs(ipo, &begin, &end);
    if (!res) {
        return 0;
    }

    mpz_init2(end_copy, 128);
    mpz_sub(end_copy, *end, *begin);
    mpz_add_ui(end_copy, end_copy, 1);
    gmp_snprintf(buf, MAX_IPV6_NUM_STR_LEN, "%Zd", end_copy);
    mpz_clear(end_copy);

    return 1;
}

/**
 * NI_size_str(): get size of Net::IP::XS object as a string.
 * @ip: Net::IP::XS object.
 * @buf: size buffer.
 *
 * See NI_size_str_ipv4() and NI_size_str_ipv6().
 */
int
NI_size_str(SV *ipo, char *size)
{
    switch (NI_hv_get_iv(ipo, "ipversion", 9)) {
        case 4:  return NI_size_str_ipv4(ipo, size);
        case 6:  return NI_size_str_ipv6(ipo, size);
        default: return 0;
    }
}

/**
 * NI_intip_str_ipv4(): get first IP address as an integer string.
 * @ip: Net::IP::XS object.
 * @buf: integer string buffer.
 */
int
NI_intip_str_ipv4(SV *ipo, char *buf)
{
    sprintf(buf, "%lu", (unsigned long) NI_hv_get_uv(ipo, "xs_v4_ip0", 9));

    return 1;
}

/**
 * NI_intip_str_ipv6(): get first IP address as an integer string.
 * @ip: Net::IP::XS object.
 * @buf: integer string buffer.
 */
int
NI_intip_str_ipv6(SV *ipo, char *buf)
{
    mpz_t *begin;

    if (!NI_get_begin_mpz(ipo, &begin)) {
        return 0;
    }

    gmp_snprintf(buf, MAX_IPV6_NUM_STR_LEN, "%Zd", *begin);

    return 1;
}

/**
 * NI_intip_str(): get first IP address as an integer string.
 * @ip: Net::IP::XS object.
 * @buf: integer string buffer.
 * @maxlen: maximum capacity of buffer.
 */
int
NI_intip_str(SV *ipo, char *buf, int maxlen)
{
    const char *intformat;
    int res;

    if ((intformat = NI_hv_get_pv(ipo, "intformat", 9))) {
        snprintf(buf, maxlen, "%s", intformat);
        return 1;
    }

    switch (NI_hv_get_iv(ipo, "ipversion", 9)) {
        case 4:  res = NI_intip_str_ipv4(ipo, buf); break;
        case 6:  res = NI_intip_str_ipv6(ipo, buf); break;
        default: res = 0;
    }

    if (res) {
        HV_MY_STORE_PV(ipo, "intformat", 9, buf, strlen(buf));
    }

    return res;
}

/**
 * NI_hexip_ipv4(): get first IP address as a hex string.
 * @ip: Net::IP::XS object.
 * @buf: hex string buffer.
 *
 * The string has '0x' prefixed to it.
 */
int
NI_hexip_ipv4(SV *ipo, char *buf)
{
    sprintf(buf, "0x%lx", (unsigned long) NI_hv_get_uv(ipo, "xs_v4_ip0", 9));

    return 1;
}

/**
 * NI_hexip_ipv6(): get first IP address as a hex string.
 * @ip: Net::IP::XS object.
 * @buf: hex string buffer.
 *
 * The string has '0x' prefixed to it.
 */
int
NI_hexip_ipv6(SV *ipo, char *hexip)
{
    mpz_t *begin;

    if (!NI_get_begin_mpz(ipo, &begin)) {
        return 0;
    }

    gmp_snprintf(hexip, MAX_IPV6_HEXIP_STR_LEN, "0x%Zx", *begin);

    return 1;
}

/**
 * NI_hexip(): get first IP address as a hex string.
 * @ip: Net::IP::XS object.
 * @buf: hex string buffer.
 * @maxlen: maximum capacity of buffer.
 *
 * See NI_hexip_ipv4() and NI_hexip_ipv6().
 */
int
NI_hexip(SV *ipo, char *buf, int maxlen)
{
    const char *hexformat;
    int res;

    if ((hexformat = NI_hv_get_pv(ipo, "hexformat", 9))) {
        snprintf(buf, maxlen, "%s", hexformat);
        return 1;
    }

    switch (NI_hv_get_iv(ipo, "ipversion", 9)) {
        case 4:  res = NI_hexip_ipv4(ipo, buf); break;
        case 6:  res = NI_hexip_ipv6(ipo, buf); break;
        default: res = 0;
    }

    if (res) {
        HV_MY_STORE_PV(ipo, "hexformat", 9, buf, strlen(buf));
    }

    return res;
}

/**
 * NI_hexmask(): return network mask as a hex string.
 * @ip: Net::IP::XS object.
 * @buf: hex string buffer.
 * @maxlen: maximum capacity of buffer.
 */
int
NI_hexmask(SV *ipo, char *buf, int maxlen)
{
    const char *binmask;
    const char *hexmask;
    mpz_t dec;

    if ((hexmask = NI_hv_get_pv(ipo, "hexmask", 7))) {
        snprintf(buf, maxlen, "%s", hexmask);
        return 1;
    }

    /* Net::IP continues with the ip_bintoint call regardless of
     * whether binmask is defined, but that won't produce reasonable
     * output anyway, so will return undef instead. */

    HV_PV_GET_OR_RETURN(binmask, ipo, "binmask", 7);

    mpz_init(dec);
    NI_ip_bintompz(binmask, strlen(binmask), &dec);
    gmp_snprintf(buf, maxlen, "0x%Zx", dec);
    mpz_clear(dec);
    HV_MY_STORE_PV(ipo, "hexmask", 7, buf, strlen(buf));

    return 1;
}

/**
 * NI_prefix(): return range in prefix format.
 * @ipo: Net::IP::XS object.
 * @buf: prefix buffer.
 * @maxlen: maximum capacity of buffer.
 *
 * Sets Error and Errno in the object if the object does not represent
 * a single prefix.
 */
int
NI_prefix(SV *ipo, char *buf, int maxlen)
{
    const char *ip;
    const char *prefix;
    int is_prefix;
    int prefixlen;

    ip = NI_hv_get_pv(ipo, "ip", 2);
    if (!ip) {
        ip = "";
    }

    is_prefix = NI_hv_get_iv(ipo, "is_prefix", 9);
    if (!is_prefix) {
        NI_object_set_Error_Errno(ipo, 209, "IP range %s is not a Prefix.", ip);
        return 0;
    }

    if ((prefix = NI_hv_get_pv(ipo, "prefix", 6))) {
        snprintf(buf, maxlen, "%s", prefix);
        return 1;
    }

    prefixlen = NI_hv_get_iv(ipo, "prefixlen", 9);
    if (prefixlen == -1) {
        return 0;
    }
    snprintf(buf, maxlen, "%s/%d", ip, prefixlen);
    HV_MY_STORE_PV(ipo, "prefix", 6, buf, 0);

    return 1;
}

/**
 * NI_mask(): return the IP address mask in IP address format.
 * @ipo: Net::IP::XS object.
 * @buf: mask buffer.
 * @maxlen: maximum capacity of buffer.
 */
int
NI_mask(SV *ipo, char *buf, int maxlen)
{
    const char *mask;
    const char *binmask;
    const char *ip;
    int is_prefix;
    int version;
    int res;

    is_prefix = NI_hv_get_iv(ipo, "is_prefix", 9);
    if (!is_prefix) {
        ip = NI_hv_get_pv(ipo, "ip", 2);
        if (!ip) {
            ip = "";
        }

        NI_object_set_Error_Errno(ipo, 209, "IP range %s is not a Prefix.", ip);
        return 0;
    }

    if ((mask = NI_hv_get_pv(ipo, "mask", 4))) {
        snprintf(buf, maxlen, "%s", mask);
        return 1;
    }

    binmask = NI_hv_get_pv(ipo, "binmask", 7);
    if (!binmask) {
        binmask = "";
    }

    version = NI_hv_get_iv(ipo, "ipversion", 9);

    res = NI_ip_bintoip(binmask, version, buf);
    if (!res) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    HV_MY_STORE_PV(ipo, "mask", 4, buf, 0);

    return 1;
}

/**
 * NI_iptype(): get the type of the first IP address in the object.
 * @ipo: Net::IP::XS object.
 * @buf: type buffer.
 * @maxlen: maximum capacity of buffer.
 *
 * See NI_ip_iptype().
 */
int
NI_iptype(SV *ipo, char *buf, int maxlen)
{
    const char *binip;
    const char *iptype;
    int version;
    int res;

    if ((iptype = NI_hv_get_pv(ipo, "iptype", 6))) {
        snprintf(buf, maxlen, "%s", iptype);
        return 1;
    }

    binip = NI_hv_get_pv(ipo, "binip", 5);
    if (!binip) {
        binip = "";
    }

    version = NI_hv_get_iv(ipo, "ipversion", 9);

    res = NI_ip_iptype(binip, version, buf);
    if (!res) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    HV_MY_STORE_PV(ipo, "iptype", 6, buf, 0);

    return 1;
}

/**
 * NI_reverse_ip(): get reverse domain for the first address of an object.
 * @ipo: Net::IP::XS object.
 * @buf: reverse domain buffer.
 *
 * See NI_ip_reverse().
 */
int
NI_reverse_ip(SV *ipo, char *buf)
{
    const char *ip;
    int prefixlen;
    int version;
    int res;

    ip = NI_hv_get_pv(ipo, "ip", 2);
    if (!ip) {
        ip = "";
    }

    if (!NI_hv_get_iv(ipo, "is_prefix", 9)) {
        NI_object_set_Error_Errno(ipo, 209, "IP range %s is not a Prefix.", ip);
        return 0;
    }

    prefixlen = NI_hv_get_iv(ipo, "prefixlen", 9);
    version   = NI_hv_get_iv(ipo, "ipversion", 9);

    res = NI_ip_reverse(ip, prefixlen, version, buf);

    if (!res) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    return 1;
}

/**
 * NI_last_bin(): get the last IP address of a range as a bitstring.
 * @ipo: Net::IP::XS object.
 * @buf: bitstring buffer.
 * @maxlen: maximum capacity of buffer.
 */
int
NI_last_bin(SV *ipo, char *buf, int maxlen)
{
    const char *last_bin;
    const char *binip;
    const char *last_ip;
    int version;
    int is_prefix;
    int prefixlen;
    int res;

    if ((last_bin = NI_hv_get_pv(ipo, "last_bin", 8))) {
        snprintf(buf, maxlen, "%s", last_bin);
        return 1;
    }

    is_prefix = NI_hv_get_iv(ipo, "is_prefix", 9);
    version   = NI_hv_get_iv(ipo, "ipversion", 9);

    if (is_prefix) {
        binip = NI_hv_get_pv(ipo, "binip", 5);
        if (!binip) {
            return 0;
        }
        prefixlen = NI_hv_get_iv(ipo, "prefixlen", 9);
        res = NI_ip_last_address_bin(binip, prefixlen, version, buf);
    } else {
        last_ip = NI_hv_get_pv(ipo, "last_ip", 7);
        if (!last_ip) {
            return 0;
        }
        res = NI_ip_iptobin(last_ip, version, buf);
    }

    if (!res) {
        NI_copy_Error_Errno(ipo);
        return 0;
    }

    buf[NI_iplengths(version)] = '\0';

    HV_MY_STORE_PV(ipo, "last_bin", 8, buf, 0);

    return 1;
}

/**
 * NI_last_int_str_ipv4(): get last IP address of a range as an integer string.
 * @ipo: Net::IP::XS object.
 * @buf: integer string buffer.
 */
int NI_last_int_str_ipv4(SV *ipo, char *buf)
{
    unsigned long end;

    end = NI_hv_get_uv(ipo, "xs_v4_ip1", 9);
    sprintf(buf, "%lu", end);

    return 1;
}

/**
 * NI_last_int_str_ipv6(): get last IP address of a range as an integer string.
 * @ipo: Net::IP::XS object.
 * @buf: integer string buffer.
 */
int NI_last_int_str_ipv6(SV *ipo, char *buf)
{
    mpz_t *end;

    if (!NI_get_end_mpz(ipo, &end)) {
        return 0;
    }

    gmp_snprintf(buf, MAX_IPV6_NUM_STR_LEN, "%Zd", *end);

    return 1;
}

/**
 * NI_last_int_str(): get last IP address of a range as an integer string.
 * @ipo: Net::IP::XS object.
 * @buf: integer string buffer.
 * @maxlen: maximum capacity of buffer.
 */
int
NI_last_int_str(SV *ipo, char *buf, int maxlen)
{
    const char *last_int;
    int res;

    if ((last_int = NI_hv_get_pv(ipo, "last_int", 8))) {
        snprintf(buf, maxlen, "%s", last_int);
        return 1;
    }

    switch (NI_hv_get_iv(ipo, "ipversion", 9)) {
        case 4:  res = NI_last_int_str_ipv4(ipo, buf); break;
        case 6:  res = NI_last_int_str_ipv6(ipo, buf); break;
        default: res = 0;
    }

    if (res) {
        HV_MY_STORE_PV(ipo, "last_int", 8, buf, 0);
    }

    return res;
}

/**
 * NI_bincomp(): compare first IP addresses of two ranges.
 * @ipo1: first Net::IP::XS object.
 * @op: the comparator as a string.
 * @ipo2: second Net::IP::XS object.
 * @buf: result buffer.
 *
 * See NI_ip_bincomp().
 */
int
NI_bincomp(SV *ipo1, const char *op, SV *ipo2, int *resbuf)
{
    const char *binip1;
    const char *binip2;
    int res;

    binip1 = NI_hv_get_pv(ipo1, "binip", 5);
    if (!binip1) {
        binip1 = "";
    }

    binip2 = NI_hv_get_pv(ipo2, "binip", 5);
    if (!binip2) {
        binip2 = "";
    }

    res = NI_ip_bincomp(binip1, op, binip2, resbuf);
    if (!res) {
        NI_copy_Error_Errno(ipo1);
        return 0;
    }

    return 1;
}

/**
 * NI_binadd(): get new object from the sum of two IP addresses.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 */
SV *
NI_binadd(SV *ipo1, SV *ipo2)
{
    const char *binip1;
    const char *binip2;
    int version;
    char binbuf[130];
    char buf[45];
    int res;
    HV *stash;
    HV *hash;
    SV *ref;
    int iplen;

    binip1 = NI_hv_get_pv(ipo1, "binip", 5);
    if (!binip1) {
        binip1 = "";
    }

    binip2 = NI_hv_get_pv(ipo2, "binip", 5);
    if (!binip2) {
        binip2 = "";
    }

    res = NI_ip_binadd(binip1, binip2, binbuf, IPV6_BITSTR_LEN);
    if (!res) {
        NI_copy_Error_Errno(ipo1);
        return NULL;
    }

    version = NI_hv_get_iv(ipo1, "ipversion", 9);
    iplen = NI_iplengths(version);
    binbuf[iplen] = '\0';
    buf[0] = '\0';

    res = NI_ip_bintoip(binbuf, version, buf);
    if (!res) {
        return NULL;
    }

    hash  = newHV();
    ref   = newRV_noinc((SV*) hash);
    stash = gv_stashpv("Net::IP::XS", 1);
    sv_bless(ref, stash);
    res = NI_set(ref, buf, version);
    if (!res) {
        return NULL;
    }

    return ref;
}

/**
 * NI_aggregate_ipv4(): aggregate two IP address ranges into new object.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 */
int
NI_aggregate_ipv4(SV *ipo1, SV *ipo2, char *buf)
{
    unsigned long b1;
    unsigned long b2;
    unsigned long e1;
    unsigned long e2;
    
    b1 = NI_hv_get_uv(ipo1, "xs_v4_ip0", 9);
    e1 = NI_hv_get_uv(ipo1, "xs_v4_ip1", 9);
    b2 = NI_hv_get_uv(ipo2, "xs_v4_ip0", 9);
    e2 = NI_hv_get_uv(ipo2, "xs_v4_ip1", 9);

    if (!NI_ip_aggregate_ipv4(b1, e1, b2, e2, 4, buf)) {
        NI_copy_Error_Errno(ipo1);
        return 0;
    }

    return 1;
}

/**
 * NI_aggregate_ipv6(): aggregate two IP address ranges into new object.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 */
int
NI_aggregate_ipv6(SV *ipo1, SV *ipo2, char *buf)
{
    mpz_t *b1_ref;
    mpz_t *e1_ref;
    mpz_t *b2_ref;
    mpz_t *e2_ref;
    mpz_t b1;
    mpz_t e1;
    mpz_t b2;
    mpz_t e2;
    int res;

    if (!NI_get_mpzs(ipo1, &b1_ref, &e1_ref)) {
        return 0;
    }
    if (!NI_get_mpzs(ipo2, &b2_ref, &e2_ref)) {
        return 0;
    }

    mpz_init2(b1, 128);
    mpz_init2(e1, 128);
    mpz_init2(b2, 128);
    mpz_init2(e2, 128);

    mpz_set(b1, *b1_ref);
    mpz_set(e1, *e1_ref);
    mpz_set(b2, *b2_ref);
    mpz_set(e2, *e2_ref);

    res = NI_ip_aggregate_ipv6(b1, e1, b2, e2, 6, buf);
    if (!res) {
        NI_copy_Error_Errno(ipo1);
    }

    mpz_clear(b1);
    mpz_clear(e1);
    mpz_clear(b2);
    mpz_clear(e2);

    return 1;
}

/**
 * NI_aggregate(): aggregate two IP address ranges into new object.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 */
SV *
NI_aggregate(SV *ipo1, SV *ipo2)
{
    int version;
    int res;
    char buf[90];
    HV *stash;
    HV *hash;
    SV *ref;

    switch ((version = NI_hv_get_iv(ipo1, "ipversion", 9))) {
        case 4:  res = NI_aggregate_ipv4(ipo1, ipo2, buf); break;
        case 6:  res = NI_aggregate_ipv6(ipo1, ipo2, buf); break;
        default: res = 0;
    }

    if (!res) {
        return 0;
    }

    hash  = newHV();
    ref   = newRV_noinc((SV*) hash);
    stash = gv_stashpv("Net::IP::XS", 1);
    sv_bless(ref, stash);
    res = NI_set(ref, buf, version);
    if (!res) {
        return NULL;
    }

    return ref;
}

/**
 * NI_overlaps_ipv4(): check if two address ranges overlap.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 * @buf: result buffer.
 */
int
NI_overlaps_ipv4(SV *ipo1, SV *ipo2, int *buf)
{
    unsigned long b1;
    unsigned long b2;
    unsigned long e1;
    unsigned long e2;
    
    b1 = NI_hv_get_uv(ipo1, "xs_v4_ip0", 9);
    e1 = NI_hv_get_uv(ipo1, "xs_v4_ip1", 9);
    b2 = NI_hv_get_uv(ipo2, "xs_v4_ip0", 9);
    e2 = NI_hv_get_uv(ipo2, "xs_v4_ip1", 9);

    NI_ip_is_overlap_ipv4(b1, e1, b2, e2, buf);

    return 1;
}

/**
 * NI_overlaps_ipv6(): check if two address ranges overlap.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 * @buf: result buffer.
 */
int
NI_overlaps_ipv6(SV *ipo1, SV *ipo2, int *buf)
{
    mpz_t *b1;
    mpz_t *e1;
    mpz_t *b2;
    mpz_t *e2;

    if (!NI_get_mpzs(ipo1, &b1, &e1)) {
        return 0;
    }
    if (!NI_get_mpzs(ipo2, &b2, &e2)) {
        return 0;
    }

    NI_ip_is_overlap_ipv6(*b1, *e1, *b2, *e2, buf);

    return 1;
}

/**
 * NI_overlaps(): check if two address ranges overlap.
 * @ipo1: first Net::IP::XS object.
 * @ipo2: second Net::IP::XS object.
 * @buf: result buffer.
 *
 * See NI_ip_is_overlap().
 */
int
NI_overlaps(SV *ipo1, SV* ipo2, int *buf)
{
    switch (NI_hv_get_iv(ipo1, "ipversion", 9)) {
        case 4:  return NI_overlaps_ipv4(ipo1, ipo2, buf);
        case 6:  return NI_overlaps_ipv6(ipo1, ipo2, buf);
        default: return 0;
    }
}

#ifdef __cplusplus
}
#endif
