% This Source Code Form is subject to the terms of the Mozilla Public
% License, v. 2.0. If a copy of the MPL was not distributed with this
% file, You can obtain one at https://mozilla.org/MPL/2.0/.
% (C) 2019 Andrey Velikiy <agreat22@gmail.com>
% (C) 2019 Fairwaves (edited) 

-module(gsup_protocol).

-include ("gsup_protocol.hrl").
-include ("ipa.hrl").

-export([decode/1, encode/1, decode_bcd/1, encode_bcd/1]).
-export_type(['GSUPMessage'/0, 'GSUPMessageType'/0]).

-define (CHECK_SIZE(IE, Len, Value),
  Value >= 0 andalso Value < (1 bsl (Len * 8)) orelse error({ie_value_length_mismatch, IE, Value})
  ).

-define (CHECK_LEN(IE, Len, Min, Max),
  Len >= Min andalso Len =< Max orelse error({ie_length_mismatch, IE, Len})
  ).

-ifdef (TEST).
-export ([encode_ie/2, decode_ie/2]).
-endif.

-spec decode(binary()) -> 'GSUPMessage'() | no_return().
decode(<<MsgType, Tail/binary>>) ->
  case ?GSUP_MESSAGES() of
    #{MsgType := #{message_type := MsgTypeAtom, mandatory := Mandatory0}} ->
      GSUPMessage = decode_ie(Tail, #{message_type => MsgTypeAtom}),
      Mandatory = Mandatory0 ++ ?MANDATORY_DEFAULT,
      case maps:size(maps:with(Mandatory, GSUPMessage)) == length(Mandatory) of
        true -> GSUPMessage;
        false -> error({mandatory_ie_missing, MsgTypeAtom, Mandatory -- maps:keys(GSUPMessage)})
      end;
    _ -> 
      error({unknown_gsup_msg_type, MsgType})
  end.

decode_ie(<<>>, Map) -> Map;

decode_ie(<<?IMSI, Len, IMSI:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(imsi, Len, 0, 8),
  decode_ie(Tail, Map#{imsi => decode_bcd(IMSI, <<>>)});

decode_ie(<<?CAUSE, Len, Cause:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(cause, Len, 1, 1),
  decode_ie(Tail, Map#{cause => Cause});

decode_ie(<<?AUTH_TUPLE, Len, AuthTuple0:Len/binary, Tail/binary>>, Map) ->
  List = maps:get(auth_tuples, Map, []),
  ?CHECK_LEN(auth_tuples, length(List) + 1, 1, 5),
  AuthTuple = decode_auth_tuple(AuthTuple0, #{}),
  check_auth_tuple(AuthTuple) orelse error({bad_auth_tuple, AuthTuple}),
  decode_ie(Tail, Map#{auth_tuples => List ++ [AuthTuple]});

decode_ie(<<?PDP_INFO_COMPLETE, Len, _:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(pdp_info_complete, Len, 0, 0),
  decode_ie(Tail, Map#{pdp_info_complete => true});

decode_ie(<<?PDP_INFO, Len, PDPInfo0:Len/binary, Tail/binary>>, Map) ->
  List = maps:get(pdp_info_list, Map, []),
  ?CHECK_LEN(pdp_info_list, length(List) + 1, 1, 10),
  PDPInfo = decode_pdp_info(PDPInfo0, #{}),
  check_pdp_info(PDPInfo) orelse error({bad_pdp_info, PDPInfo}),
  decode_ie(Tail, Map#{pdp_info_list => List ++ [PDPInfo]});

decode_ie(<<?CANCELLATION_TYPE, Len, CancellationType:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(cancellation_type, Len, 1, 1),
  decode_ie(Tail, Map#{cancellation_type => CancellationType});

decode_ie(<<?FREEZE_P_TMSI, Len, _:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(freeze_p_tmsi, Len, 0, 0),
  decode_ie(Tail, Map#{freeze_p_tmsi => true});

decode_ie(<<?MSISDN, Len, MSISDN:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(msisdn, Len, 0, 8),
  decode_ie(Tail, Map#{msisdn => MSISDN});

decode_ie(<<?HLR_NUMBER, Len, HLRNumber:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(hlr_number, Len, 0, 8),
  decode_ie(Tail, Map#{hlr_number => HLRNumber});

decode_ie(<<?MESSAGE_CLASS, Len, MessageClass:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(message_class, Len, 1, 1),
  decode_ie(Tail, Map#{message_class => MessageClass});

decode_ie(<<?PDP_CONTEXT_ID, Len, PDPContextId:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(pdp_context_id, Len, 1, 1),
  List = maps:get(pdp_context_id, Map, []),
  ?CHECK_LEN(pdp_context_id_list, length(List) + 1, 1, 10),
  decode_ie(Tail, Map#{pdp_context_id => List ++ [PDPContextId]});

decode_ie(<<?PDP_CHARGING, Len, PDPCharging:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(pdp_charging, Len, 2, 2),
  decode_ie(Tail, Map#{pdp_charging => PDPCharging});

decode_ie(<<?RAND, Len, Rand:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(rand, Len, 16, 16),
  decode_ie(Tail, Map#{rand => Rand});

decode_ie(<<?AUTS, Len, AUTS:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(auts, Len, 14, 14),
  decode_ie(Tail, Map#{auts => AUTS});

decode_ie(<<?CN_DOMAIN, Len, CN_Domain:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(cn_domain, Len, 1, 1),
  decode_ie(Tail, Map#{cn_domain => CN_Domain});

decode_ie(<<?SUPPORTED_RAT_TYPES, Len, Rat_Type:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(supported_rat_types, Len, 1, 8),
  decode_ie(Tail, Map#{supported_rat_types => decode_rat_types(binary_to_list(Rat_Type))});

decode_ie(<<?CURRENT_RAT_TYPE, Len, Rat_Type:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(current_rat_type, Len, 1, 1),
  decode_ie(Tail, Map#{current_rat_type => decode_rat_type(Rat_Type)});

decode_ie(<<?SESSION_ID, Len, SesID:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(session_id, Len, 4, 4),
  decode_ie(Tail, Map#{session_id => SesID});

decode_ie(<<?SESSION_STATE, Len, SesState:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(session_state, Len, 1, 1),
  decode_ie(Tail, Map#{session_state => SesState});

decode_ie(<<?SS_INFO, Len, SesInfo:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{ss_info => SesInfo});

decode_ie(<<?SM_RP_MR, Len, MsgRef:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(sm_rp_mr, Len, 1, 1),
  decode_ie(Tail, Map#{sm_rp_mr => MsgRef});

decode_ie(<<?SM_RP_DA, Len, DA:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_da => DA});

decode_ie(<<?SM_RP_OA, Len, OA:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_oa => OA});

decode_ie(<<?SM_RP_UI, Len, MessageBody:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_rp_ui => MessageBody});

decode_ie(<<?SM_RP_CAUSE, Len, RPCause:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(sm_rp_cause, Len, 1, 1),
  decode_ie(Tail, Map#{sm_rp_cause => RPCause});

decode_ie(<<?SM_RP_MMS, Len, RPMMS:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(sm_rp_mms, Len, 1, 1),
  decode_ie(Tail, Map#{sm_rp_mms => RPMMS});

decode_ie(<<?SM_ALERT_REASON, Len, AlertReason:Len/unit:8, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{sm_alert_reason => AlertReason});

decode_ie(<<?IMEI, Len, IMEI:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(imei, Len, 9, 9),
  decode_ie(Tail, Map#{imei => IMEI});

decode_ie(<<?IMEI_CHECK_RESULT, Len, IMEIResult:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(imei_check_result, Len, 1, 1),
  decode_ie(Tail, Map#{imei_check_result => IMEIResult});

decode_ie(<<?NUM_VECTORS_REQ, Len, NUM_VECTORS_REQ:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(num_vectors_req, Len, 1, 1),
  decode_ie(Tail, Map#{num_vectors_req => NumVectorsRequest});

decode_ie(<<?SOURCE_NAME, Len, SourceName:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{source_name => SourceName});

decode_ie(<<?DESTINATION_NAME, Len, DestName:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{destination_name => DestName});

decode_ie(<<?AN_APDU, Len, AN_APDU:Len/binary, Tail/binary>>, Map) ->
  decode_ie(Tail, Map#{an_apdu => AN_APDU});

decode_ie(<<?RR_CAUSE, Len, RRCause:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(rr_cause, Len, 1, 1),
  decode_ie(Tail, Map#{rr_cause => RRCause});

decode_ie(<<?BSSAP_CAUSE, Len, BSSAPCause:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(bssap_cause, Len, 1, 1),
  decode_ie(Tail, Map#{bssap_cause => BSSAPCause});

decode_ie(<<?SESSION_MANAGEMENT_CAUSE, Len, SMCause:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(session_management_cause, Len, 1, 1),
  decode_ie(Tail, Map#{session_management_cause => SMCause});

decode_ie(<<_, Len, _:Len/binary, Tail/binary>>, Map) -> %% skip unknown IE
  decode_ie(Tail, Map);

decode_ie(X, Map) ->
  error({cannot_decode_ie, X, Map}).

-spec decode_bcd(binary()) -> binary().
decode_bcd(BCDNumber) -> decode_bcd(BCDNumber, <<>>).

decode_bcd(<<>>, Number) -> Number;

decode_bcd(<<A:4, B:4, Tail/binary>>, Number) when A < 15, B < 15 ->
  decode_bcd(Tail, <<Number/binary, (decode_nibble(B)), (decode_nibble(A))>>);

decode_bcd(<<_:4, B:4, _Tail/binary>>, Number) when B < 15 ->
  <<Number/binary, (decode_nibble(B))>>.

decode_nibble(0) -> $0;
decode_nibble(1) -> $1;
decode_nibble(2) -> $2;
decode_nibble(3) -> $3;
decode_nibble(4) -> $4;
decode_nibble(5) -> $5;
decode_nibble(6) -> $6;
decode_nibble(7) -> $7;
decode_nibble(8) -> $8;
decode_nibble(9) -> $9;
decode_nibble(10) -> $*;
decode_nibble(11) -> $#;
decode_nibble(12) -> $a;
decode_nibble(13) -> $b;
decode_nibble(14) -> $c.

decode_auth_tuple(<<?RAND, Len, Rand:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(rand, Len, 16, 16),
  decode_auth_tuple(Tail, Map#{rand => Rand});

decode_auth_tuple(<<?SRES, Len, SRES:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(sres, Len, 4, 4),
  decode_auth_tuple(Tail, Map#{sres => SRES});

decode_auth_tuple(<<?KC, Len, KC:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(kc, Len, 8, 8),
  decode_auth_tuple(Tail, Map#{kc => KC});

decode_auth_tuple(<<?IK, Len, IK:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(ik, Len, 16, 16),
  decode_auth_tuple(Tail, Map#{ik => IK});

decode_auth_tuple(<<?CK, Len, CK:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(ck, Len, 16, 16),
  decode_auth_tuple(Tail, Map#{ck => CK});

decode_auth_tuple(<<?AUTN, Len, AUTN:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(autn, Len, 16, 16),
  decode_auth_tuple(Tail, Map#{autn => AUTN});

decode_auth_tuple(<<?RES, Len, Res:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(res, Len, 0, 16),
  decode_auth_tuple(Tail, Map#{res => Res});

decode_auth_tuple(<<>>, Map) -> Map.

decode_pdp_info(<<?PDP_CONTEXT_ID, Len, PDPContextId:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(pdp_context_id, Len, 1, 1),
  decode_pdp_info(Tail, Map#{pdp_context_id => PDPContextId});

decode_pdp_info(<<?PDP_TYPE, Len, PDPType:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(pdp_type, Len, 2, 2),
  decode_pdp_info(Tail, Map#{pdp_type => PDPType});

decode_pdp_info(<<?ACCESS_POINT_NAME, Len, APN:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(access_point_name, Len, 1, 100),
  decode_pdp_info(Tail, Map#{access_point_name => APN});

decode_pdp_info(<<?QUALITY_OF_SERVICE, Len, QOS:Len/binary, Tail/binary>>, Map) ->
  ?CHECK_LEN(quality_of_service, Len, 1, 20),
  decode_pdp_info(Tail, Map#{quality_of_service => QOS});

decode_pdp_info(<<?PDP_CHARGING, Len, PDPCharging:Len/unit:8, Tail/binary>>, Map) ->
  ?CHECK_LEN(pdp_charging, Len, 2, 2),
  decode_pdp_info(Tail, Map#{pdp_charging => PDPCharging});

decode_pdp_info(<<>>, Map) -> Map.

decode_rat_type(0) -> rat_unknown;
decode_rat_type(1) -> rat_geran_a;
decode_rat_type(2) -> rat_utran_iu;
decode_rat_type(3) -> rat_eutran_sgs.

decode_rat_types([], Acc) -> lists:reverse(Acc);
decode_rat_types([Head|Tail], Acc) ->
	T = decode_rat_type(Head),
	decode_rat_types(Tail, [T|Acc]).
decode_rat_types(List) -> decode_rat_types(List, []).

-spec encode('GSUPMessage'()) -> binary() | no_return().
encode(GSUPMessage = #{message_type := MsgTypeAtom}) when is_atom(MsgTypeAtom) ->
  F = fun
    (MsgType_, #{message_type := MsgTypeAtom_}, undefined) when MsgTypeAtom_ == MsgTypeAtom -> MsgType_;
    (_, _, Acc) -> Acc
  end,
  case maps:fold(F, undefined, ?GSUP_MESSAGES()) of
    undefined -> error({unknown_message_type, MsgTypeAtom}), MsgType = undefined;
    MsgType when is_integer(MsgType) -> ok
  end,
  encode(MsgType, GSUPMessage).

encode(MsgType, GSUPMessage) when is_integer(MsgType), is_map(GSUPMessage), MsgType >=0, MsgType =< 255 ->
  case ?GSUP_MESSAGES() of
    #{MsgType := #{message_type := MsgTypeAtom, mandatory := Mandatory0} = Map} ->
      Mandatory = Mandatory0 ++ ?MANDATORY_DEFAULT,
      Possible = Mandatory ++ maps:get(optional, Map, []) ++ ?OPTIONAL_DEFAULT,
      case {maps:size(maps:with(Mandatory, GSUPMessage)) == length(Mandatory),
            maps:size(maps:without(Possible, GSUPMessage)) == 0} of
        {true, true} -> 
          Tail = encode_ie(GSUPMessage, <<>>),
          <<MsgType, Tail/binary>>;
        {false, _} -> error({mandatory_ie_missing, MsgTypeAtom, Mandatory -- maps:keys(GSUPMessage)});
        {_, false} -> error({ie_not_expected, MsgTypeAtom, maps:keys(GSUPMessage) -- Possible})
      end;
    _ -> 
      error({unknown_gsup_msg_type, MsgType})
  end.

encode_ie(#{imsi := Value0} = GSUPMessage, Head) ->
  Value = encode_bcd(Value0, <<>>),
  Len = size(Value),
  ?CHECK_LEN(imsi, Len, 0, 8),
  encode_ie(maps:without([imsi], GSUPMessage), <<Head/binary, ?IMSI, Len, Value/binary>>);

encode_ie(#{cause := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(cause, Len, Value),
  encode_ie(maps:without([cause], GSUPMessage), <<Head/binary, ?CAUSE, Len, Value:Len/unit:8>>);

encode_ie(#{auth_tuples := Tuples0} = GSUPMessage, Head) ->
  ?CHECK_LEN(auth_tuples, length(Tuples0), 0, 5),
  Tuples = <<
    begin
      check_auth_tuple(Tuple) orelse error({bad_auth_tuple, Tuple}),
      Value = encode_auth_tuple(Tuple, <<>>),
      Len = size(Value),
      <<?AUTH_TUPLE, Len, Value/binary>>
    end || Tuple <- Tuples0>>,
  encode_ie(maps:without([auth_tuples], GSUPMessage), <<Head/binary, Tuples/binary>>);

encode_ie(#{msisdn := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  ?CHECK_LEN(msisdn, Len, 0, 8),
  encode_ie(maps:without([msisdn], GSUPMessage), <<Head/binary, ?MSISDN, Len, Value/binary>>);

encode_ie(#{hlr_number := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  ?CHECK_LEN(hlr_number, Len, 0, 8),
  encode_ie(maps:without([hlr_number], GSUPMessage), <<Head/binary, ?HLR_NUMBER, Len, Value/binary>>);

encode_ie(#{pdp_info_complete := true} = GSUPMessage, Head) ->
  encode_ie(maps:without([pdp_info_complete], GSUPMessage), <<Head/binary, ?PDP_INFO_COMPLETE, 0>>);

encode_ie(#{pdp_info_complete := _} = _GSUPMessage, _Head) ->
  error(pdp_info_complete_must_be_true);

encode_ie(#{pdp_info_list := PDPInfoList0} = GSUPMessage, Head) -> %% PDPInfo
  ?CHECK_LEN(pdp_info_list, length(PDPInfoList0), 0, 10),
  PDPInfoList = <<
    begin
      check_pdp_info(PDPInfo) orelse error({bad_pdp_info, PDPInfo}),
      Value = encode_pdp_info(PDPInfo, <<>>),
      Len = size(Value),
      <<?PDP_INFO, Len, Value/binary>>
    end || PDPInfo <- PDPInfoList0>>,
  encode_ie(maps:without([pdp_info_list], GSUPMessage), <<Head/binary, PDPInfoList/binary>>);

encode_ie(#{cancellation_type := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(cancellation_type, Len, Value),
  encode_ie(maps:without([cancellation_type], GSUPMessage), <<Head/binary, ?CANCELLATION_TYPE, Len, Value:Len/unit:8>>);

encode_ie(#{freeze_p_tmsi := true} = GSUPMessage, Head) ->
  encode_ie(maps:without([freeze_p_tmsi], GSUPMessage), <<Head/binary, ?FREEZE_P_TMSI, 0>>);

encode_ie(#{freeze_p_tmsi := _} = _GSUPMessage, _Head) ->
  error(freeze_p_tmsi_must_be_true);

encode_ie(#{session_id := Value} = GSUPMessage, Head) ->
  Len = 4,
  ?CHECK_SIZE(session_id, Len, Value),
  encode_ie(maps:without([session_id], GSUPMessage), <<Head/binary, ?SESSION_ID, Len, Value:Len/unit:8>>);

encode_ie(#{session_state := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(session_state, Len, Value),
  encode_ie(maps:without([session_state], GSUPMessage), <<Head/binary, ?SESSION_STATE, Len, Value:Len/unit:8>>);

encode_ie(#{message_class := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(message_class, Len, Value),
  encode_ie(maps:without([message_class], GSUPMessage), <<Head/binary, ?MESSAGE_CLASS, Len, Value:Len/unit:8>>);

encode_ie(#{pdp_context_id := PDPCIdList0} = GSUPMessage, Head) ->
  Len = 1,
  PDPCIdList = <<
    begin
      ?CHECK_SIZE(pdp_context_id, Len, Value),
      <<?PDP_CONTEXT_ID, Len, Value:Len/unit:8>>
    end || Value <- PDPCIdList0>>,
  encode_ie(maps:without([pdp_context_id], GSUPMessage), <<Head/binary, PDPCIdList/binary>>);

encode_ie(#{pdp_charging := Value} = GSUPMessage, Head) ->
  Len = 2,
  ?CHECK_SIZE(pdp_charging, Len, Value),
  encode_ie(maps:without([pdp_charging], GSUPMessage), <<Head/binary, ?PDP_CHARGING, Len, Value:Len/unit:8>>);

encode_ie(#{auts := Value} = GSUPMessage, Head) ->
  Len = 14,
  ?CHECK_LEN(auts, size(Value), Len, Len),
  encode_ie(maps:without([auts], GSUPMessage), <<Head/binary, ?AUTS, Len, Value:Len/binary>>);

encode_ie(#{rand := Value} = GSUPMessage, Head) ->
  Len = 16,
  ?CHECK_LEN(rand, size(Value), Len, Len),
  encode_ie(maps:without([rand], GSUPMessage), <<Head/binary, ?RAND, Len, Value:Len/binary>>);

encode_ie(#{cn_domain := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(cn_domain, Len, Value),
  encode_ie(maps:without([cn_domain], GSUPMessage), <<Head/binary, ?CN_DOMAIN, Len, Value:Len/unit:8>>);

encode_ie(#{supported_rat_types := Value} = GSUPMessage, Head) when is_list(Value) ->
  Len = length(Value),
  ?CHECK_LEN(supported_rat_types, Len, 1, 8),
  RatList = encode_rat_types(Value),
  encode_ie(maps:without([supported_rat_types], GSUPMessage), <<Head/binary, ?SUPPORTED_RAT_TYPES, Len, RatList/binary>>);

encode_ie(#{current_rat_type := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_LEN(current_rat_type, Len, 1, 1),
  Rat = encode_rat_type(Value),
  encode_ie(maps:without([current_rat_type], GSUPMessage), <<Head/binary, ?CURRENT_RAT_TYPE, Len, Rat:Len/unit:8>>);

encode_ie(#{ss_info := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([ss_info], GSUPMessage), <<Head/binary, ?SS_INFO, Len, Value/binary>>);

encode_ie(#{sm_rp_mr := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(sm_rp_mr, Len, Value),
  encode_ie(maps:without([sm_rp_mr], GSUPMessage), <<Head/binary, ?SM_RP_MR, Len, Value:Len/unit:8>>);

encode_ie(#{sm_rp_da := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([sm_rp_da], GSUPMessage), <<Head/binary, ?SM_RP_DA, Len, Value/binary>>);

encode_ie(#{sm_rp_oa := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([sm_rp_oa], GSUPMessage), <<Head/binary, ?SM_RP_OA, Len, Value/binary>>);

encode_ie(#{sm_rp_ui := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([sm_rp_ui], GSUPMessage), <<Head/binary, ?SM_RP_UI, Len, Value/binary>>);

encode_ie(#{sm_rp_cause := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(sm_rp_cause, Len, Value),
  encode_ie(maps:without([sm_rp_cause], GSUPMessage), <<Head/binary, ?SM_RP_CAUSE, Len, Value:Len/unit:8>>);

encode_ie(#{sm_rp_mms := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(sm_rp_mms, Len, Value),
  encode_ie(maps:without([sm_rp_mms], GSUPMessage), <<Head/binary, ?SM_RP_MMS, Len, Value:Len/unit:8>>);

encode_ie(#{sm_alert_reason := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(sm_alert_reason, Len, Value),
  encode_ie(maps:without([sm_alert_reason], GSUPMessage), <<Head/binary, ?SM_ALERT_REASON, Len, Value:Len/unit:8>>);

encode_ie(#{imei := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  ?CHECK_LEN(imei, Len, 9, 9),
  encode_ie(maps:without([imei], GSUPMessage), <<Head/binary, ?IMEI, Len, Value/binary>>);

encode_ie(#{imei_check_result := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(imei_check_result, Len, Value),
  encode_ie(maps:without([imei_check_result], GSUPMessage), <<Head/binary, ?IMEI_CHECK_RESULT, Len, Value:Len/unit:8>>);

encode_ie(#{num_vectors_req := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(num_vectors_req, Len, Value),
  encode_ie(maps:without([num_vectors_req], GSUPMessage), <<Head/binary, ?NUM_VECTORS_REQ, Len, Value:Len/unit:8>>);

encode_ie(#{source_name := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([source_name], GSUPMessage), <<Head/binary, ?SOURCE_NAME, Len, Value/binary>>);

encode_ie(#{destination_name := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([destination_name], GSUPMessage), <<Head/binary, ?DESTINATION_NAME, Len, Value/binary>>);

encode_ie(#{an_apdu := Value} = GSUPMessage, Head) ->
  Len = size(Value),
  encode_ie(maps:without([an_apdu], GSUPMessage), <<Head/binary, ?AN_APDU, Len, Value/binary>>);

encode_ie(#{rr_cause := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(rr_cause, Len, Value),
  encode_ie(maps:without([rr_cause], GSUPMessage), <<Head/binary, ?RR_CAUSE, Len, Value:Len/unit:8>>);

encode_ie(#{bssap_cause := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(bssap_cause, Len, Value),
  encode_ie(maps:without([bssap_cause], GSUPMessage), <<Head/binary, ?BSSAP_CAUSE, Len, Value:Len/unit:8>>);

encode_ie(#{session_management_cause := Value} = GSUPMessage, Head) ->
  Len = 1,
  ?CHECK_SIZE(session_management_cause, Len, Value),
  encode_ie(maps:without([session_management_cause], GSUPMessage), <<Head/binary, ?SESSION_MANAGEMENT_CAUSE, Len, Value:Len/unit:8>>);

encode_ie(_, Head) -> Head.

encode_bcd(BCDNumber) -> encode_bcd(BCDNumber, <<>>).

encode_bcd(<<A, B, Tail/binary>>, BCDNumber) ->
  encode_bcd(Tail, <<BCDNumber/binary, (encode_nibble(B)):4, (encode_nibble(A)):4>>);

encode_bcd(<<A>>, BCDNumber) ->
  <<BCDNumber/binary, 16#f:4, (encode_nibble(A)):4>>;

encode_bcd(<<>>, BCDNumber) ->
  BCDNumber.

encode_nibble($0) -> 0;
encode_nibble($1) -> 1;
encode_nibble($2) -> 2;
encode_nibble($3) -> 3;
encode_nibble($4) -> 4;
encode_nibble($5) -> 5;
encode_nibble($6) -> 6;
encode_nibble($7) -> 7;
encode_nibble($8) -> 8;
encode_nibble($9) -> 9;
encode_nibble($*) -> 10;
encode_nibble($#) -> 11;
encode_nibble($a) -> 12;
encode_nibble($b) -> 13;
encode_nibble($c) -> 14;
encode_nibble($A) -> 12;
encode_nibble($B) -> 13;
encode_nibble($C) -> 14;
encode_nibble(X) -> error({bad_bcd_character, X}).

check_auth_tuple(AuthTuple) ->
  Mandatory = ?AUTH_TUPLE_MANDATORY,
  Possible = Mandatory ++ ?AUTH_TUPLE_OPTIONAL,
  (maps:size(maps:with(Mandatory, AuthTuple)) == length(Mandatory))
    orelse error({mandatory_ie_missing, auth_tuples, Mandatory -- maps:keys(AuthTuple)}),
  (maps:size(maps:without(Possible, AuthTuple)) == 0)
    orelse error({ie_not_expected, auth_tuples, maps:keys(AuthTuple) -- Possible}).

check_pdp_info(PDPInfo) ->
  Mandatory = ?PDP_INFO_MANDATORY,
  Possible = Mandatory ++ ?PDP_INFO_OPTIONAL,
  (maps:size(maps:with(Mandatory, PDPInfo)) == length(Mandatory))
    orelse error({mandatory_ie_missing, pdp_info_list, Mandatory -- maps:keys(PDPInfo)}),
  (maps:size(maps:without(Possible, PDPInfo)) == 0)
    orelse error({ie_not_expected, pdp_info_list, maps:keys(PDPInfo) -- Possible}).

encode_auth_tuple(#{rand := Value} = Map, Head) ->
  Len = 16,
  ?CHECK_LEN(rand, size(Value), Len, Len),
  encode_auth_tuple(maps:without([rand], Map), <<Head/binary, ?RAND, Len, Value:Len/binary>>);

encode_auth_tuple(#{sres := Value} = Map, Head) ->
  Len = 4,
  ?CHECK_LEN(sres, size(Value), Len, Len),
  encode_auth_tuple(maps:without([sres], Map), <<Head/binary, ?SRES, Len, Value:Len/binary>>);

encode_auth_tuple(#{kc := Value} = Map, Head) ->
  Len = 8,
  ?CHECK_LEN(kc, size(Value), Len, Len),
  encode_auth_tuple(maps:without([kc], Map), <<Head/binary, ?KC, Len, Value:Len/binary>>);

encode_auth_tuple(#{ik := Value} = Map, Head) ->
  Len = 16,
  ?CHECK_LEN(ik, size(Value), Len, Len),
  encode_auth_tuple(maps:without([ik], Map), <<Head/binary, ?IK, Len, Value:Len/binary>>);

encode_auth_tuple(#{ck := Value} = Map, Head) ->
  Len = 16,
  ?CHECK_LEN(ck, size(Value), Len, Len),
  encode_auth_tuple(maps:without([ck], Map), <<Head/binary, ?CK, Len, Value:Len/binary>>);

encode_auth_tuple(#{autn := Value} = Map, Head) ->
  Len = 16,
  ?CHECK_LEN(autn, size(Value), Len, Len),
  encode_auth_tuple(maps:without([autn], Map), <<Head/binary, ?AUTN, Len, Value:Len/binary>>);

encode_auth_tuple(#{res := Value} = Map, Head) ->
  Len = size(Value),
  ?CHECK_LEN(res, size(Value), Len, Len),
  encode_auth_tuple(maps:without([res], Map), <<Head/binary, ?RES, Len, Value/binary>>);

encode_auth_tuple(#{}, Head) -> Head.

encode_pdp_info(#{pdp_context_id := Value} = Map, Head) ->
  Len = 1,
  ?CHECK_SIZE(pdp_context_id, Len, Value),
  encode_pdp_info(maps:without([pdp_context_id], Map), <<Head/binary, ?PDP_CONTEXT_ID, Len, Value:Len/unit:8>>);

encode_pdp_info(#{pdp_type := Value} = Map, Head) ->
  Len = 2,
  ?CHECK_SIZE(pdp_type, Len, Value),
  encode_pdp_info(maps:without([pdp_type], Map), <<Head/binary, ?PDP_TYPE, Len, Value:Len/unit:8>>);

encode_pdp_info(#{access_point_name := Value} = Map, Head) ->
  Len = size(Value),
  ?CHECK_LEN(access_point_name, Len, 1, 100),
  encode_pdp_info(maps:without([access_point_name], Map), <<Head/binary, ?ACCESS_POINT_NAME, Len, Value/binary>>);

encode_pdp_info(#{quality_of_service := Value} = Map, Head) ->
  Len = size(Value),
  ?CHECK_LEN(quality_of_service, Len, 1, 20),
  encode_pdp_info(maps:without([quality_of_service], Map), <<Head/binary, ?QUALITY_OF_SERVICE, Len, Value/binary>>);

encode_pdp_info(#{pdp_charging := Value} = Map, Head) ->
  Len = 2,
  ?CHECK_SIZE(pdp_charging, Len, Value),
  encode_pdp_info(maps:without([pdp_charging], Map), <<Head/binary, ?PDP_CHARGING, Len, Value:Len/unit:8>>);

encode_pdp_info(#{}, Head) -> Head.

encode_rat_type(rat_unknown) -> 0;
encode_rat_type(rat_geran_a) -> 1;
encode_rat_type(rat_utran_iu) -> 2;
encode_rat_type(rat_eutran_sgs) -> 3.

encode_rat_types([], Acc) -> list_to_binary(lists:reverse(Acc));
encode_rat_types([Head|Tail], Acc) ->
	T = encode_rat_type(Head),
	encode_rat_types(Tail, [T|Acc]).
encode_rat_types(List) -> encode_rat_types(List, []).
