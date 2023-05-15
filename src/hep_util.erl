%% Copyright (c) 2013, Matthias Endler <matthias.endler@pantech.at>
%%
%% Permission to use, copy, modify, and distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

%% @private
-module(hep_util).

-include("hep.hrl").

-export([timestamp_secs/1]).
-export([timestamp_microsecs/1]).
-export([payload_type/1]).
-export([protocol_family/1]).

%% API

-spec timestamp_secs (erlang:timestamp()) -> non_neg_integer().
timestamp_secs ({M, S, _U}) ->
    M * 1000000 + S.

-spec timestamp_microsecs (erlang:timestamp()) -> non_neg_integer().
timestamp_microsecs ({_M, _S, U}) ->
    U.

-spec payload_type (hep:uint8() | hep:payload_type()) ->
                           hep:payload_type() | hep:uint8() | {error, _}.
payload_type (?PROTOCOL_RESERVED) -> 'reserved';
payload_type (?PROTOCOL_SIP) -> 'sip';
payload_type (?PROTOCOL_XMPP) -> 'xmpp';
payload_type (?PROTOCOL_SDP) -> 'sdp';
payload_type (?PROTOCOL_RTP) -> 'rtp';
payload_type (?PROTOCOL_RTCP) -> 'rtcp';
payload_type (?PROTOCOL_MGCP) -> 'mgcp';
payload_type (?PROTOCOL_MEGACO) -> 'megaco';
payload_type (?PROTOCOL_M2UA) -> 'm2ua';
payload_type (?PROTOCOL_M3UA) -> 'm3ua';
payload_type (?PROTOCOL_IAX) -> 'iax';
payload_type (?PROTOCOL_H322) -> 'h322';
payload_type (?PROTOCOL_H321) -> 'h321';
payload_type (?PROTOCOL_M2PA) -> 'm2pa';
payload_type (?PROTOCOL_MOS_FULL) -> 'mos_full';
payload_type (?PROTOCOL_MOS_SHORT) -> 'mos_short';
payload_type (?PROTOCOL_SIP_JSON) -> 'sip_json';
payload_type (?PROTOCOL_DNS_JSON) -> 'dns_json';
payload_type (?PROTOCOL_M3UA_JSON) -> 'm3ua_json';
payload_type (?PROTOCOL_RTSP) -> 'rtsp';
payload_type (?PROTOCOL_DIAMETER) -> 'diameter';
payload_type (?PROTOCOL_GSM_MAP) -> 'gsm_map';
payload_type (?PROTOCOL_RTCP_PION) -> 'rtcp_pion';
payload_type (?PROTOCOL_CDR) -> 'cdr';
payload_type (?PROTOCOL_LOG) -> 'log';
payload_type ('reserved') -> ?PROTOCOL_RESERVED;
payload_type ('sip') -> ?PROTOCOL_SIP;
payload_type ('xmpp') -> ?PROTOCOL_XMPP;
payload_type ('sdp') -> ?PROTOCOL_SDP;
payload_type ('rtp') -> ?PROTOCOL_RTP;
payload_type ('rtcp') -> ?PROTOCOL_RTCP;
payload_type ('mgcp') -> ?PROTOCOL_MGCP;
payload_type ('megaco') -> ?PROTOCOL_MEGACO;
payload_type ('m2ua') -> ?PROTOCOL_M2UA;
payload_type ('m3ua') -> ?PROTOCOL_M3UA;
payload_type ('iax') -> ?PROTOCOL_IAX;
payload_type ('h322') -> ?PROTOCOL_H322;
payload_type ('h321') -> ?PROTOCOL_H321;
payload_type ('m2pa') -> ?PROTOCOL_M2PA;
payload_type ('mos_full') -> ?PROTOCOL_MOS_FULL;
payload_type ('mos_short') -> ?PROTOCOL_MOS_SHORT;
payload_type ('sip_json') -> ?PROTOCOL_SIP_JSON;
payload_type ('dns_json') -> ?PROTOCOL_DNS_JSON;
payload_type ('m3ua_json') -> ?PROTOCOL_M3UA_JSON;
payload_type ('rtsp') -> ?PROTOCOL_RTSP;
payload_type ('diameter') -> ?PROTOCOL_DIAMETER;
payload_type ('gsm_map') -> ?PROTOCOL_GSM_MAP;
payload_type ('rtcp_pion') -> ?PROTOCOL_RTCP_PION;
payload_type ('cdr') -> ?PROTOCOL_CDR;
payload_type ('log') -> ?PROTOCOL_LOG;
payload_type (Protocol) ->
    {error, {invalid_protocol, Protocol}}.

-spec protocol_family (hep:uint8() | hep:protocol_family()) ->
                             hep:protocol_family() | hep:uint8() | {error, _}.
protocol_family (?FAMILY_IPV4) -> 'ipv4';
protocol_family (?FAMILY_IPV6) -> 'ipv6';
protocol_family ('ipv4') -> ?FAMILY_IPV4;
protocol_family ('ipv6') -> ?FAMILY_IPV6;
protocol_family (ProtocolFamily) ->
    {error, {invalid_protocol_family, ProtocolFamily}}.

%% Internals

%% End of Module.
