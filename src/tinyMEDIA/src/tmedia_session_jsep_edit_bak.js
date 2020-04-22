/*
* Copyright (C) 2012-2018 Doubango Telecom <http://www.doubango.org>
* License: BSD
* This file is part of Open Source sipML5 solution <http://www.sipml5.org>
*/
// http://tools.ietf.org/html/draft-uberti-rtcweb-jsep-02
// JSEP00: webkitPeerConnection00 (http://www.w3.org/TR/2012/WD-webrtc-20120209/)
// JSEP01: webkitRTCPeerConnection (http://www.w3.org/TR/webrtc/), https://webrtc-demos.appspot.com/html/pc1.html
// Mozilla: http://mozilla.github.com/webrtc-landing/pc_test.html
// Contraints: https://webrtc-demos.appspot.com/html/constraints-and-stats.html
// Android: https://groups.google.com/group/discuss-webrtc/browse_thread/thread/b8538c85df801b40
// Canary 'muted': https://groups.google.com/group/discuss-webrtc/browse_thread/thread/8200f2049c4de29f
// Canary state events: https://groups.google.com/group/discuss-webrtc/browse_thread/thread/bd30afc3e2f43f6d
// DTMF: https://groups.google.com/group/discuss-webrtc/browse_thread/thread/1354781f202adbf9
// IceRestart: https://groups.google.com/group/discuss-webrtc/browse_thread/thread/c189584d380eaa97
// Video Resolution: https://code.google.com/p/chromium/issues/detail?id=143631#c9
// Webrtc-Everywhere: https://github.com/sarandogou/webrtc-everywhere
// Adapter.js: https://github.com/sarandogou/webrtc

tmedia_session_jsep.prototype = Object.create(tmedia_session.prototype);
tmedia_session_jsep01.prototype = Object.create(tmedia_session_jsep.prototype);

tmedia_session_jsep.prototype.o_pc = null;
tmedia_session_jsep.prototype.b_cache_stream = false;
tmedia_session_jsep.prototype.o_local_stream = null;
tmedia_session_jsep.prototype.o_sdp_jsep_lo = null;
tmedia_session_jsep.prototype.o_sdp_lo = null;
tmedia_session_jsep.prototype.b_sdp_lo_pending = false;
tmedia_session_jsep.prototype.i_sdp_lo_version = -1;
tmedia_session_jsep.prototype.o_sdp_json_ro = null;
tmedia_session_jsep.prototype.o_sdp_ro = null;
tmedia_session_jsep.prototype.b_sdp_ro_pending = false;
tmedia_session_jsep.prototype.b_sdp_ro_offer = false;
tmedia_session_jsep.prototype.s_answererSessionId = null;
tmedia_session_jsep.prototype.s_offererSessionId = null;
tmedia_session_jsep.prototype.ao_ice_servers = null;
tmedia_session_jsep.prototype.o_bandwidth = { audio:undefined, video:undefined };
tmedia_session_jsep.prototype.o_video_size = { minWidth:undefined, minHeight:undefined, maxWidth:undefined, maxHeight:undefined };
tmedia_session_jsep.prototype.o_video_framerate = { minFrameRate:undefined, maxFrameRate:undefined };

tmedia_session_jsep.prototype.b_ro_changed = false;
tmedia_session_jsep.prototype.b_lo_held = true;
tmedia_session_jsep.prototype.b_ro_held = false;
tmedia_session_jsep.prototype.s_screenShareId = null;
tmedia_session_jsep.prototype.s_screenStream = null;
tmedia_session_jsep.prototype.s_sendrecv = null;
tmedia_session_jsep.prototype.iTypHost = 0;
tmedia_session_jsep.prototype.iTcpSum = 0;
tmedia_session_jsep.prototype.b_stream_max = true;
tmedia_session_jsep.prototype.o_pc_sdp = null;
tmedia_session_jsep.prototype.sIceState = null;
tmedia_session_jsep.prototype.iIceTimerId = null;
tmedia_session_jsep.prototype.arrVideoCandidata = new Array();
tmedia_session_jsep.prototype.arrAudioCandidata = new Array();
tmedia_session_jsep.prototype.recvVideoCandidata = new Array();
tmedia_session_jsep.prototype.recvAudioCandidata = new Array();
tmedia_session_jsep.prototype.localSdpHeaderO = null;
tmedia_session_jsep.prototype.arrAudioSdpHdr = new Array();
tmedia_session_jsep.prototype.arrVideoSdpHdr = new Array();
tmedia_session_jsep.prototype.bNoIceSupport = true;
tmedia_session_jsep.prototype.bAnswerCompleted = false;
tmedia_session_jsep.prototype.bRemoteBfcp = false;
tmedia_session_jsep.prototype.bAddAudioCodec = false;

//
//  JSEP
//

tmedia_session_jsep.prototype.CreateInstance = function (o_mgr) {
    return new tmedia_session_jsep01(o_mgr);
}

function tmedia_session_jsep(o_mgr) {
    tmedia_session.call(this, o_mgr.e_type, o_mgr);
}

tmedia_session_jsep.prototype.__set = function (o_param) {
    if (!o_param) {
        return -1;
    }
    switch (o_param.s_key) {
        case 'ice-servers':
        {
            this.ao_ice_servers = o_param.o_value;
            return 0;
        }
        case 'cache-stream':
        {
            this.b_cache_stream = !!o_param.o_value;
            return 0;
        }
        case 'bandwidth':
        {
            this.o_bandwidth = o_param.o_value;
            return 0;
        }
        case 'video-size':
        {
            this.o_video_size = o_param.o_value;
            return 0;
        }
        case 'video-framerate':
        {
            this.o_video_framerate = o_param.o_value;
            return 0;
        }
        case 'screencast-windowid':
        {
            this.d_screencast_windowid = parseFloat(o_param.o_value.toString());
            if (this.o_pc && this.o_pc.setScreencastSrcWindowId) {
                this.o_pc.setScreencastSrcWindowId(this.d_screencast_windowid);
            }
            return 0;
        }
        case 'mute-audio':
        case 'mute-video':
        {
            if (this.o_pc && typeof o_param.o_value == "boolean") {
                if (this.o_pc.mute) {
                    this.o_pc.mute((o_param.s_key === 'mute-audio') ? "audio" : "video", o_param.o_value);
                }
                else if (this.o_local_stream) {
                    var tracks = (o_param.s_key === 'mute-audio') ? this.o_local_stream.getAudioTracks() : this.o_local_stream.getVideoTracks();
                    if (tracks) {
                        for (var i = 0; i < tracks.length; ++i) {
                            tracks[i].enabled = !o_param.o_value;
                        }
                    }
                }
            }
        }
    }

    return -2;
}

tmedia_session_jsep.prototype.__prepare = function () {
    return 0;
}

tmedia_session_jsep.prototype.__set_media_type = function (e_type) {
    if (e_type != this.e_type) {
        this.e_type = e_type;
        this.o_sdp_lo = null;
    }
    return 0;
}

tmedia_session_jsep.prototype.__processContent = function (s_req_name, s_content_type, s_content_ptr, i_content_size) {
    if (this.o_pc && this.o_pc.processContent) {
        this.o_pc.processContent(s_req_name, s_content_type, s_content_ptr, i_content_size);
        return 0;
    }
    return -1;
}

tmedia_session_jsep.prototype.__send_dtmf = function (s_digit) {
    if (this.o_pc && this.o_pc.sendDTMF) {
        this.o_pc.sendDTMF(s_digit);
        return 0;
    }
    return -1;
}

tmedia_session_jsep.prototype.__start = function () {
    tsk_utils_log_info("tmedia_session_jsep: __start()");
    if (this.o_local_stream && this.o_local_stream.start) {
        // cached stream would be stopped in close()
        tsk_utils_log_info("tmedia_session_jsep: o_local_stream.start()");
        this.o_local_stream.start();
    }
    return 0;
}

tmedia_session_jsep.prototype.__pause = function () {
    if (this.o_local_stream && this.o_local_stream.pause) {
        this.o_local_stream.pause();
    }
    return 0;
}

tmedia_session_jsep.prototype.__stop = function () {
    this.close();
    this.o_sdp_lo = null;
    tsk_utils_log_info("jsep PeerConnection::stop()");

    return 0;
}

tmedia_session_jsep.prototype.decorate_lo = function (b_inc_version) {
    tsk_utils_log_info("enter decorate_lo");
    if (this.o_sdp_lo) {
        tsk_utils_log_info("old local sdp: "+this.o_sdp_lo.toString());
        /* Session name for debugging - Requires by webrtc2sip to set RTCWeb type */
        var o_hdr_S;
        if ((o_hdr_S = this.o_sdp_lo.get_header(tsdp_header_type_e.S))) {
            o_hdr_S.s_value = "Doubango Telecom - " + tsk_utils_get_navigator_friendly_name();
        }

        /* HACK: https://bugzilla.mozilla.org/show_bug.cgi?id=1072384 */
        var o_hdr_O;
        if ((o_hdr_O = this.o_sdp_lo.get_header(tsdp_header_type_e.O))) {
            if (o_hdr_O.s_addr === "0.0.0.0") {
                o_hdr_O.s_addr = "127.0.0.1";
            }
            var This = this;
            if(o_hdr_O.s_addr === "127.0.0.1" && This.arrAudioCandidata.length > 0) {
                var oCandidate = tsk_string_parse_candidates(This.arrAudioCandidata);

                if (oCandidate && oCandidate.ipaddr) {
                    tsk_utils_log_info("parse audio sdp ip: "+oCandidate.ipaddr);
                    o_hdr_O.s_addr = oCandidate.ipaddr;
                }
            }
        }

        if (this.bNoIceSupport) {
            this.localSdpHeaderO = this.o_sdp_lo.get_header_a("msid-semantic");
            this.o_sdp_lo.remove_header_by_field("msid-semantic");
        }

        if (this.e_type == tmedia_type_e.AUDIO_VIDEO) {
            var o_hdr_Group = this.o_sdp_lo.get_header_a("group");
            if (!o_hdr_Group) {
                //tsk_utils_log_warn("decorate_lo: add BUNDLE to o_sdp_lo.");
                //this.o_sdp_lo.add_header(new tsdp_header_A("group", "BUNDLE audio video"));
            }
        } else if (this.e_type == tmedia_type_e.AUDIO) {
            this.o_sdp_lo.remove_header_by_field("group");
            this.o_sdp_lo.add_header(new tsdp_header_A("group", "BUNDLE audio"));
        }

        /* Session version */
        var o_hdr_O;
        if (this.i_sdp_lo_version == -1) {
            this.i_sdp_lo_version = ((__o_peerconnection_class == window.webkitRTCPeerConnection)/* || (__o_peerconnection_class == w4aPeerConnection)*/) ? 2 : 1; // 1: google-ice, 2: standard-ice
        }
        if ((o_hdr_O = this.o_sdp_lo.get_header(tsdp_header_type_e.O))) {
            o_hdr_O.i_sess_version = this.i_sdp_lo_version;
            tsk_utils_log_info("sdp lo version: "+this.i_sdp_lo_version+", b_inc: "+b_inc_version);
            if (b_inc_version) {
                ++this.i_sdp_lo_version;
            }
        }
        /* Remove 'video' media if not enabled (bug in chrome: doesn't honor 'has_video' parameter) */
        if (/*!this.o_sdp_ro &&*/!(this.e_type.i_id & tmedia_type_e.VIDEO.i_id)) {
            this.o_sdp_lo.remove_media("video");
        }

        /* hold / resume, profile, bandwidth... */
        var This = this;
        var i_index = 0;
        var o_hdr_M;
        var b_fingerprint = !!this.o_sdp_lo.get_header_a("fingerprint"); // session-level fingerprint
        while ((o_hdr_M = this.o_sdp_lo.get_header_at(tsdp_header_type_e.M, i_index++))) {
            // hold/resume
            tsk_utils_log_info(">>>> set_holdresume_att lo_held:"+this.b_lo_held+" ro_held:"+this.b_ro_held);
            o_hdr_M.set_holdresume_att(this.b_lo_held, this.b_ro_held);
            // HACK: Nightly 20.0a1 uses RTP/SAVPF for DTLS-SRTP which is not correct. More info at https://bugzilla.mozilla.org/show_bug.cgi?id=827932.
            /*
         var o_hdr_a_crypto = o_hdr_M.find_a("crypto");
             if (o_hdr_a_crypto) {
                 o_hdr_a_crypto.RemoveAllByField(o_hdr_M.ao_hdr_A,"crypto");
             }

         var o_hdr_a_fingerprint = o_hdr_M.find_a("fingerprint");
             if (o_hdr_a_fingerprint) {
                 o_hdr_a_fingerprint.RemoveAllByField(o_hdr_M.ao_hdr_A,"fingerprint");
             }
         */
            var o_hdr_a_tcp = o_hdr_M.find_a("candidate");
            if(o_hdr_M.s_media.toLowerCase() == "audio" && This.arrAudioCandidata.length > 0) {
                var oCandidate = tsk_string_parse_candidates(This.arrAudioCandidata);

                if (oCandidate && oCandidate.ipaddr && oCandidate.port) {
                    tsk_utils_log_info("parse audio sdp ip: "+oCandidate.ipaddr+" port: "+oCandidate.port);
                    o_hdr_M.i_port = parseInt(oCandidate.port);
                    o_hdr_M.o_hdr_C.s_addr = oCandidate.ipaddr;

                    var o_rtcp_a = o_hdr_M.find_a("rtcp");
                    if (o_rtcp_a) {
                        o_rtcp_a.s_value = oCandidate.port+" IN IP4 "+oCandidate.ipaddr;
                    }
                }

                for (var i=0; i<This.arrAudioCandidata.length; i++) {
                    if (This.arrAudioCandidata[i] && This.arrAudioCandidata[i].candidate) {
                        if (!this.bNoIceSupport && !o_hdr_a_tcp)
                            o_hdr_M.add_header(new tsdp_header_A(This.arrAudioCandidata[i].candidate));
                    }
                }
                This.arrAudioCandidata.splice(0, This.arrAudioCandidata.length);
            }
            else if(o_hdr_M.s_media.toLowerCase() == "video" && This.arrVideoCandidata.length > 0) {
                var oCandidate = tsk_string_parse_candidates(This.arrVideoCandidata);

                if (oCandidate && oCandidate.ipaddr && oCandidate.port) {
                    tsk_utils_log_info("parse video sdp ip: "+oCandidate.ipaddr+" port: "+oCandidate.port);
                    o_hdr_M.i_port = parseInt(oCandidate.port);
                    o_hdr_M.o_hdr_C.s_addr = oCandidate.ipaddr;

                    var o_rtcp_a = o_hdr_M.find_a("rtcp");
                    if (o_rtcp_a) {
                        o_rtcp_a.s_value = oCandidate.port+" IN IP4 "+oCandidate.ipaddr;
                    }
                }

                for (var i=0; i<This.arrVideoCandidata.length; i++) {
                    if (This.arrVideoCandidata[i] && This.arrVideoCandidata[i].candidate) {
                        if (!this.bNoIceSupport && !o_hdr_a_tcp)
                            o_hdr_M.add_header(new tsdp_header_A(This.arrVideoCandidata[i].candidate));
                    }
                }
                This.arrVideoCandidata.splice(0, This.arrVideoCandidata.length);
            }

            if (o_hdr_a_tcp) {
                o_hdr_a_tcp.RemoveAllByValue(o_hdr_M.ao_hdr_A, " tcp ");
            }

            var o_ice_a = o_hdr_M.find_a("ice-ufrag");
            if (this.bNoIceSupport && o_ice_a) {
                o_hdr_M.s_proto = "RTP/AVP";
                o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "candidate");
                o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "extmap");
                o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "crypto");
                if (o_hdr_M.s_media.toLowerCase() == "video") {
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-pwd", this.arrVideoSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-options", this.arrVideoSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-ufrag", this.arrVideoSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ssrc-group", this.arrVideoSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ssrc", this.arrVideoSdpHdr);
                } else {
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-pwd", this.arrAudioSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-options", this.arrAudioSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-ufrag", this.arrAudioSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ssrc-group", this.arrAudioSdpHdr);
                    o_ice_a.RemoveAllByField(o_hdr_M.ao_hdr_A, "ssrc", this.arrAudioSdpHdr);
                }

            }

            if (o_hdr_M.find_a("crypto")) {
                o_hdr_M.s_proto = "RTP/SAVPF";
            }
            else if (b_fingerprint || o_hdr_M.find_a("fingerprint")) {
                o_hdr_M.s_proto = "UDP/TLS/RTP/SAVPF";
            }
            /*
             o_hdr_M.s_proto = "RTP/AVP";
             var o_hdr_a_candidate = o_hdr_M.find_a("candidate");
             if (o_hdr_a_candidate) {
             o_hdr_a_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A,"candidate");
             }
                 */
            // HACK: https://bugzilla.mozilla.org/show_bug.cgi?id=1072384
            if (o_hdr_M.o_hdr_C && o_hdr_M.o_hdr_C.s_addr === "0.0.0.0") {
                o_hdr_M.o_hdr_C.s_addr = "127.0.0.1";
            }

            // bandwidth
            if(this.o_bandwidth) {
                o_hdr_M.remove_header_b();
                if(this.o_bandwidth.audio && o_hdr_M.s_media.toLowerCase() == "audio") {
                    o_hdr_M.add_header(new tsdp_header_B("AS:"+this.o_bandwidth.audio));
                }
                else if(this.o_bandwidth.video && o_hdr_M.s_media.toLowerCase() == "video") {
                    o_hdr_M.add_header(new tsdp_header_B("AS:"+this.o_bandwidth.video));
                }
            }
        }
    }

    if ( 0 && Platform && Platform.OS && Platform.OS === 'ios' &&
        this.e_type == tmedia_type_e.VIDEO && oAudioMediaSession ) {
        tsk_utils_log_info("decorate_lo: video plus audio.");
        var oMediaSdp = new tsdp_message();
        oMediaSdp.ao_headers = oAudioMediaSession.o_sdp_lo.ao_headers.concat();
        var oHdrVideo = this.o_sdp_lo.get_header(tsdp_header_type_e.M);
        if (oHdrVideo) {
            tsk_utils_log_info("decorate_lo: add video header.");
            oMediaSdp.add_header(oHdrVideo);
        }

        var oHdrGroup = oMediaSdp.get_header_a("group");
        if (oHdrGroup) {
            tsk_utils_log_info("decorate_lo: modify sdp group.");
            oHdrGroup.s_value = "BUNDLE audio video";
        }

        this.o_sdp_lo = oMediaSdp;
        //this.o_sdp_lo.ao_headers = oAudioMediaSession.o_sdp_lo.ao_headers.concat(this.o_sdp_lo.ao_headers);
    }
    return 0;
}

tmedia_session_jsep.prototype.decorate_ro = function (b_remove_bundle) {
    if (this.o_sdp_ro) {
        var o_hdr_M, o_hdr_A;
        var i_index = 0, i;

        // FIXME: Chrome fails to parse SDP with global SDP "a=" attributes
        // Chrome 21.0.1154.0+ generate "a=group:BUNDLE audio video" but cannot parse it
        // In fact, new the attribute is left the ice callback is called twice and the 2nd one trigger new INVITE then 200OK. The SYN_ERR is caused by the SDP in the 200 OK.
        // Is it because of "a=rtcp:1 IN IP4 0.0.0.0"?
        if (b_remove_bundle) {
            this.o_sdp_ro.remove_header(tsdp_header_type_e.A);
        }

        // ==== START: RFC5939 utility functions ==== //
        var rfc5939_get_acap_part = function (o_hdr_a, i_part/* i_part = 1: field, 2: value*/) {
            var ao_match = o_hdr_a.s_value.match(/^\d\s+(\w+):([\D|\d]+)/i);
            if (ao_match && ao_match.length == 3) {
                return ao_match[i_part];
            }
        }
        var rfc5939_acap_ensure = function (o_hdr_a) {
            if (o_hdr_a && o_hdr_a.s_field == "acap") {
                o_hdr_a.s_field = rfc5939_get_acap_part(o_hdr_a, 1);
                o_hdr_a.s_value = rfc5939_get_acap_part(o_hdr_a, 2);
            }
        }
        var rfc5939_get_headerA_at = function (o_msg, s_media, s_field, i_index) {
            var i_pos = 0;
            var get_headerA_at = function (o_sdp, s_field, i_index) {
                if (o_sdp) {
                    var ao_headersA = (o_sdp.ao_headers || o_sdp.ao_hdr_A);
                    for (var i = 0; i < ao_headersA.length; ++i) {
                        if (ao_headersA[i].e_type == tsdp_header_type_e.A && ao_headersA[i].s_value) {
                            var b_found = (ao_headersA[i].s_field === s_field);
                            if (!b_found && ao_headersA[i].s_field == "acap") {
                                b_found = (rfc5939_get_acap_part(ao_headersA[i], 1) == s_field);
                            }
                            if (b_found && i_pos++ >= i_index) {
                                return ao_headersA[i];
                            }
                        }
                    }
                }
            }

            var o_hdr_a = get_headerA_at(o_msg, s_field, i_index); // find at session level
            if (!o_hdr_a) {
                return get_headerA_at(o_msg.get_header_m_by_name(s_media), s_field, i_index); // find at media level
            }
            return o_hdr_a;
        }
        // ==== END: RFC5939 utility functions ==== //

        // change profile if not secure
        //!\ firefox nighly: DTLS-SRTP only, chrome: SDES-SRTP
        var b_fingerprint = !!this.o_sdp_ro.get_header_a("fingerprint"); // session-level fingerprint
        var s_holdresume;

        if ( 0 && Platform && Platform.OS && Platform.OS === 'ios' &&
            this.e_type == tmedia_type_e.VIDEO && oAudioMediaSession ) {
            tsk_utils_log_info(">>> decorate_ro parse audio sdp.");
            var oAudioSdp = new tsdp_message();
            oAudioSdp.ao_headers = this.o_sdp_ro.ao_headers.concat();
            oAudioSdp.remove_media("video");
            oAudioMediaSession.o_mgr.set_ro(oAudioSdp, false);
        }

        tsk_utils_log_info(">>> decorate_ro remove audio sdp.");
        if (this.e_type == tmedia_type_e.VIDEO) {
            this.o_sdp_ro.remove_media("audio");
        }

        if (this.bNoIceSupport)
            this.o_sdp_ro.remove_header_by_fielbAddWmsd("msid-semantic");

        var sIpaddr = this.o_sdp_ro.get_header_o_addr();
        var bAddWms = false;
        this.bRemoteBfcp = this.o_sdp_ro.remove_bfcp_media();

        while ((o_hdr_M = this.o_sdp_ro.get_header_at(tsdp_header_type_e.M, i_index++))) {
            if (o_hdr_M.s_media.toLowerCase() == "video") {
                s_holdresume = o_hdr_M.get_holdresume_att();
                if (s_holdresume) {
                    tsk_utils_log_info("s_holdresume: "+s_holdresume);
                    this.s_sendrecv = s_holdresume;
                    //if (s_holdresume == 'sendonly') {
                    //    this.b_lo_held = true;
                    //    this.b_ro_held = false;
                    //}
                }
            }
            if (this.bAddAudioCodec && o_hdr_M.s_media.toLowerCase() == "audio") {
                if (o_hdr_M.as_fmt.length == 1 && o_hdr_M.as_fmt[0] == "8") {
                    o_hdr_M.as_fmt.splice(0,1);
                    o_hdr_M.as_fmt = ["111", "103", "104", "9", "102", "0", "8", "106", "105", "13", "110", "112", "113", "126"];

                    for (var j = 0; j<o_hdr_M.ao_hdr_A.length; j++) {
                        if (o_hdr_M.ao_hdr_A[j].s_field == "rtpmap" && o_hdr_M.ao_hdr_A[j].s_value == "8 PCMA/8000") {
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "111 opus/48000/2"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "103 ISAC/16000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "104 ISAC/32000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "9 G722/8000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "102 ILBC/8000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "0 PCMU/8000"));
                            j++; // 8 PCMA/8000
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "106 CN/32000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "105 CN/16000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "13 CN/8000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "110 telephone-event/48000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "112 telephone-event/32000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "113 telephone-event/16000"));
                            o_hdr_M.ao_hdr_A.splice(j++, 0 ,new tsdp_header_A("rtpmap", "126 telephone-event/8000"));
                            break;
                        }
                    }
                }
            }

            if (o_hdr_M.s_media.toLowerCase() == "audio") {
                if (o_hdr_M.as_fmt.length == 1 && o_hdr_M.as_fmt[0] == "8") {
                    var o_hdr_fmtp = o_hdr_M.find_a("rtpmap");
                    if (o_hdr_fmtp) {
                        o_hdr_fmtp.RemoveAllByField(o_hdr_M.ao_hdr_A, "rtcp-fb");
                        o_hdr_fmtp.RemoveAllByField(o_hdr_M.ao_hdr_A, "rtpmap");
                    }
                }
            }

            //"a=rtcp-mux a=rtcp:24682 IN IP4 192.168.78.250"
            var o_hdr_rtcp = o_hdr_M.find_a("rtcp-mux");
            if (this.bNoIceSupport && !o_hdr_rtcp) {
                if (sIpaddr && o_hdr_M.i_port) {
                    o_hdr_M.add_header(new tsdp_header_A("rtcp-mux"));
                    o_hdr_M.add_header(new tsdp_header_A("rtcp", o_hdr_M.i_port+" IN IP4 "+sIpaddr));
                }
            }

            // fmtp:111 minptime=10;useinbandfec=1
            if (this.bAddAudioCodec && o_hdr_M.s_media.toLowerCase() == "audio") {
                o_hdr_M.add_header(new tsdp_header_A("fmtp", "111 minptime=10;useinbandfec=1"));
            }

            var o_hdr_candidate = o_hdr_M.find_a("candidate");
            if (this.bNoIceSupport && o_hdr_candidate && o_hdr_M.s_media.toLowerCase() == "video") {
                o_hdr_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-pwd");
                o_hdr_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A, "ice-ufrag");
                o_hdr_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A, "ssrc-group");
                o_hdr_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A, "ssrc");
                o_hdr_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A, "candidate");
                o_hdr_candidate.RemoveAllByField(o_hdr_M.ao_hdr_A, "end-of-candidates");
            }

            if (this.bNoIceSupport && !o_hdr_candidate && sIpaddr && o_hdr_M.i_port) {
                if (!bAddWms) {
                    var m_index = this.o_sdp_ro.get_header_m_index("audio");
                    this.o_sdp_ro.ao_headers.splice(m_index, 0, new tsdp_header_A("msid-semantic", " WMS TWy5tPPJI8VzhazszQjr0LOqYyuflbf4"));
                    bAddWms = true;
                }

                var s_candidate = "4704976692 1 udp 659136 "+sIpaddr+" "+o_hdr_M.i_port+" typ host generation 0";
                tsk_utils_log_info("add remote sdp "+s_candidate);
                if (o_hdr_M.s_media.toLowerCase() == "audio") {
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "1001010086 cname:XE0hjFQREChMDG42"));
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "1001010086 msid:TWy5tPPJI8VzhazszQjr0LOqYyuflbf4 a0"));
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "1001010086 mslabel:TWy5tPPJI8VzhazszQjr0LOqYyuflbf4"));
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "1001010086 label:TWy5tPPJI8VzhazszQjr0LOqYyuflbf4a0"));

                    o_hdr_M.add_header(new tsdp_header_A("ice-ufrag", "ndjeOYuCmPIyQOtE"));
                    o_hdr_M.add_header(new tsdp_header_A("ice-pwd", "ijLsOraiUhUnOPf1Sp6xdq0q"));

                    o_hdr_M.add_header(new tsdp_header_A("candidate", s_candidate));
                    o_hdr_M.add_header(new tsdp_header_A("end-of-candidates"));
                } else {
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "0 cname:XE0hjFQREChMDG42"));
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "0 msid:TWy5tPPJI8VzhazszQjr0LOqYyuflbf4 v0"));
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "0 mslabel:TWy5tPPJI8VzhazszQjr0LOqYyuflbf4"));
                    o_hdr_M.add_header(new tsdp_header_A("ssrc", "0 label:TWy5tPPJI8VzhazszQjr0LOqYyuflbf4v0"));

                    o_hdr_M.add_header(new tsdp_header_A("ice-ufrag", "yiDxkFoU3lYGGckj"));
                    o_hdr_M.add_header(new tsdp_header_A("ice-pwd", "UQ6CVAk9PwUZGem4mPrwlFge"));

                    o_hdr_M.add_header(new tsdp_header_A("candidate", s_candidate));
                    o_hdr_M.add_header(new tsdp_header_A("end-of-candidates"));
                }

                if (o_hdr_M.s_media.toLowerCase() == "video" && this.arrVideoSdpHdr.length > 0) {
                    //o_hdr_M.ao_hdr_A = o_hdr_M.ao_hdr_A.concat(this.arrVideoSdpHdr);
                    this.arrVideoSdpHdr.splice(0, this.arrVideoSdpHdr.length);
                } else if (o_hdr_M.s_media.toLowerCase() == "audio" && this.arrAudioSdpHdr.length > 0) {
                    //o_hdr_M.ao_hdr_A = o_hdr_M.ao_hdr_A.concat(this.arrAudioSdpHdr);
                    this.arrAudioSdpHdr.splice(0, this.arrAudioSdpHdr.length);
                }


            }

            if(o_hdr_M.s_media.toLowerCase() == "audio") {
                for (var i=0; i<o_hdr_M.ao_hdr_A.length; i++) {
                    if (o_hdr_M.ao_hdr_A[i] && o_hdr_M.ao_hdr_A[i].s_field == "candidate") {
                        var oCandidate = {
                            candidate: "candidate:"+o_hdr_M.ao_hdr_A[i].s_value,
                            sdpMLineIndex: i,
                            sdpMid: "audio"
                        };
                        this.recvAudioCandidata.push(oCandidate);
                    }
                }
            }
            else if(o_hdr_M.s_media.toLowerCase() == "video") {
                for (var i=0; i<o_hdr_M.ao_hdr_A.length; i++) {
                    if (o_hdr_M.ao_hdr_A[i] && o_hdr_M.ao_hdr_A[i].s_field == "candidate") {
                        var oCandidate = {
                            candidate: "candidate:"+o_hdr_M.ao_hdr_A[i].s_value,
                            sdpMLineIndex: i,
                            sdpMid: "video"
                        };
                        this.recvVideoCandidata.push(oCandidate);
                    }
                }
            }

            // check for "crypto:"/"fingerprint:" lines (event if it's not valid to provide "crypto" lines in non-secure SDP many clients do it, so, just check)
            if (o_hdr_M.s_proto.indexOf("SAVP") < 0) {
                if (o_hdr_M.find_a("crypto")) {
                    o_hdr_M.s_proto = "RTP/SAVPF";
                    break;
                }
                else if (b_fingerprint || o_hdr_M.find_a("fingerprint")) {
                    o_hdr_M.s_proto = "UDP/TLS/RTP/SAVPF";
                    break;
                }
            }

            // rfc5939: "acap:fingerprint,setup,connection"
            if (o_hdr_M.s_proto.indexOf("SAVP") < 0) {
                if ((o_hdr_A = rfc5939_get_headerA_at(this.o_sdp_ro, o_hdr_M.s_media, "fingerprint", 0))) {
                    rfc5939_acap_ensure(o_hdr_A);
                    if ((o_hdr_A = rfc5939_get_headerA_at(this.o_sdp_ro, o_hdr_M.s_media, "setup", 0))) {
                        rfc5939_acap_ensure(o_hdr_A);
                    }
                    if ((o_hdr_A = rfc5939_get_headerA_at(this.o_sdp_ro, o_hdr_M.s_media, "connection", 0))) {
                        rfc5939_acap_ensure(o_hdr_A);
                    }
                    o_hdr_M.s_proto = "UDP/TLS/RTP/SAVP";
                }
            }
            // rfc5939: "acap:crypto". Only if DTLS is OFF
            if (o_hdr_M.s_proto.indexOf("SAVP") < 0) {
                i = 0;
                while ((o_hdr_A = rfc5939_get_headerA_at(this.o_sdp_ro, o_hdr_M.s_media, "crypto", i++))) {
                    rfc5939_acap_ensure(o_hdr_A);
                    o_hdr_M.s_proto = "RTP/SAVPF";
                    // do not break => find next "acap:crypto" lines and ensure them
                }
            }

            // HACK: Nightly 20.0a1 uses RTP/SAVPF for DTLS-SRTP which is not correct. More info at https://bugzilla.mozilla.org/show_bug.cgi?id=827932
            // Same for chrome: https://code.google.com/p/sipml5/issues/detail?id=92
            if (o_hdr_M.s_proto.indexOf("UDP/TLS/RTP/SAVP") != -1) {
                //o_hdr_M.s_proto = "RTP/SAVPF";
            }
        }
    }
    return 0;
}

tmedia_session_jsep.prototype.subscribe_stream_events = function () {
    if (this.o_pc) {
        var This = (tmedia_session_jsep01.mozThis || this);
        this.o_pc.onaddstream = function (evt) {
            tsk_utils_log_info("*** haha __on_add_stream");
            This.o_remote_stream = evt.stream;
            tsk_utils_log_info("*** haha the id of evt stream "+evt.stream.id);
            if (This.o_mgr) {
                if (This.o_mgr && This.o_mgr.b_recvonly) {
                    tsk_utils_log_info("=====>>> haha the recvdonly video stream .......");
                    This.b_lo_held = true;
                    This.o_mgr.set_stream_local(null);
                    if (This.o_pc && This.o_local_stream) {
                        This.o_pc.removeStream(This.o_local_stream);
                        //This.o_local_stream.stop();
                        This.o_local_stream = null;
                    }
                    This.o_mgr.set_stream_remote(evt.stream);
                    This.decorate_lo(true);
                } else if (This.o_mgr && This.o_mgr.b_sendonly) {
                    tsk_utils_log_info("=====>>> haha the sendonly video stream .......");
                    This.b_ro_held = true;
                    This.o_mgr.set_stream_remote(null);
                    if (This.o_pc && This.o_remote_stream) {
                        This.o_pc.removeStream(This.o_remote_stream);
                        This.o_remote_stream = null;
                    }
                    This.decorate_lo(true);
                } else {
                    tsk_utils_log_info("=====>>> haha the sendrecv video stream .......");
                    This.o_mgr.set_stream_remote(evt.stream);
                }
            }
        }
        this.o_pc.onremovestream = function (evt) {
            tsk_utils_log_info("__on_remove_stream");
            This.o_remote_stream = null;
            if (This.o_mgr) {
                This.o_mgr.set_stream_remote(null);
            }
        }
    }
}

tmedia_session_jsep.prototype.close = function () {
    if (this.o_mgr) { // 'onremovestream' not always called
        this.o_mgr.set_stream_remote(null);
        this.o_mgr.set_stream_local(null);
    }
    if (this.o_pc) {
        if (this.o_local_stream) {
            // TODO: On Firefox 26: Error: "removeStream not implemented yet"
            try {
                this.o_pc.removeStream(this.o_local_stream);
                tsk_utils_log_info("release and stop local stream.");
                if (tsk_mcs_type_is_rnapp() && this.o_local_stream.release)
                    this.o_local_stream.release();

                tsk_utils_stop_stream(this.o_local_stream);
            } catch (e) { tsk_utils_log_error(e); }

            //if (!this.b_cache_stream && (this.s_screenStream==null)/* || (this.e_type == tmedia_type_e.SCREEN_SHARE)*/) { // only stop if caching is disabled or screenshare
            //    try { tsk_utils_stop_stream(this.o_local_stream); }
            //    catch (e) { tsk_utils_log_error(e); } // Deprecated in Chrome 45: https://github.com/DoubangoTelecom/sipml5/issues/231
            //}
            this.o_local_stream = null;
        }
        this.o_pc.close();
        this.o_pc = null;
        this.b_sdp_lo_pending = false;
        this.b_sdp_ro_pending = false;
    }
}

tmedia_session_jsep.prototype.__acked = function () {
    return 0;
}

tmedia_session_jsep.prototype.__hold = function () {
    if (this.b_lo_held) {
        // tsk_utils_log_warn('already on hold');
        return;
    }
    this.b_lo_held = true;

    this.close();

    this.o_sdp_ro = null;
    this.o_sdp_lo = null;
    tsk_utils_log_warn('on hold....');

    if (this.o_pc && this.o_local_stream) {
        this.o_pc.removeStream(this.o_local_stream);
    }

    return 0;
}

tmedia_session_jsep.prototype.reload_lo = function () {

    this.b_lo_held = false;

    this.close();

    this.o_sdp_lo = null;
    this.o_sdp_ro = null;
    //this.decorate_lo(true);

    return 0;
}

tmedia_session_jsep.prototype.__resume = function () {
    if (!this.b_lo_held) {
        // tsk_utils_log_warn('not on hold');
        return;
    }
    this.b_lo_held = false;

    this.close();

    this.o_sdp_lo = null;
    this.o_sdp_ro = null;

    if (this.o_pc && this.o_local_stream) {
        this.o_pc.addStream(this.o_local_stream);
    }

    return 0;
}

tmedia_session_jsep.prototype.SetlocalStream = function (o_stream) {

    if (o_stream) {
        this.o_pc.removeStream(this.o_local_stream);
        this.o_local_stream.release();
        this.o_local_stream = o_stream;
        tsk_utils_log_info("change local media stream.");

        this.o_pc.addStream(o_stream);
    } else {
        tsk_utils_log_info("remove local media stream.");
        this.o_pc.removeStream(this.o_local_stream);
    }

}

tmedia_session_jsep.prototype.set_sendrecv = function (b_lo_held, b_ro_held) {
    tsk_utils_log_info("media session jsep.set_sendrecv: "+b_lo_held+"|"+b_ro_held);
    tsk_utils_log_info("media session jsep : "+this.b_lo_held+"|"+this.b_ro_held);
    if (!this.b_lo_held && this.b_ro_held) {
        return;
    }
    this.b_lo_held = b_lo_held;
    this.b_ro_held = b_ro_held;
    this.decorate_lo(true);
}

tmedia_session_jsep.prototype.get_sendrecv = function () {
    if (this.s_sendrecv) {
        return this.s_sendrecv;
    }
    return null;
}

tmedia_session_jsep.prototype.getStreamBandwidth = function(callBack, number){
    var o_info = {};
    var This = this;
    var funcCB = callBack;
    var iNumber = number;

    o_info.send = 0;
    o_info.receive = 0;
    o_info.sent = 0;
    o_info.lost = 0;

    if (This.o_pc && This.o_pc.getStats) {
        //tsk_utils_log_info("...get pc stats...");
        This.o_pc.getStats(function(response){
            var reports = response.result();
            var bVideoBwe=false,bSsrc=false;
            //tsk_utils_log_info("...get report stats success, size: "+reports.length);
            for (var i in reports) {
                var report = reports[i];
                var names =  report.names();

                if (report.type != "VideoBwe" && report.type != "ssrc") {
                    continue;
                }
                if (report.type == "VideoBwe")
                    bVideoBwe = true;
                else if (report.type == "ssrc")
                    bSsrc = true;

                //tsk_utils_log_info("...get "+report.type+" report values size: "+names.length);
                for(var j in names){
                    var value = report.stat(names[j]);
                    if (names[j]!="googAvailableSendBandwidth"&&names[j]!="googAvailableReceiveBandwidth"&&names[j]!="packetsSent"&&names[j]!="packetsLost")
                        continue;

                    //tsk_utils_log_info("...get name: "+names[j]+" value: "+value);
                    if (names[j] == "googAvailableSendBandwidth") {
                        o_info.send = value;
                    } else if (names[j] == "googAvailableReceiveBandwidth") {
                        o_info.receive = value;
                    } else if (names[j] == "packetsSent") {
                        o_info.sent = value;
                    } else if (names[j] == "packetsLost") {
                        o_info.lost = value;
                    }
                }
                if (bVideoBwe && bSsrc) {
                    //tsk_utils_log_info("return stream bandwidth send: "+o_info.send+" recv: "+o_info.receive+" sent: "+o_info.sent+" lost: "+o_info.lost);
                    funcCB(iNumber, o_info);
                    return;
                }
            }
            funcCB(iNumber, o_info);
            return;
        });
    } else {
        funcCB(iNumber, o_info);
    }
}

tmedia_session_jsep.prototype.set_video_stream = function (b_max) {
    tsk_utils_log_info("set video stream: "+b_max);
    this.b_stream_max = b_max;
    if (this.b_stream_max) {
        //this.o_pc.setLocalDescription(this.o_pc_sdp, null, null);
        //this.o_pc.addStream(__o_media_stream_video);
        this.o_pc.removeStream(__o_media_stream_video_min);
        this.o_pc.removeStream(__o_media_stream_video);
        this.o_local_stream = __o_media_stream_video;
        //this.o_pc.addStream(__o_media_stream_video_min);
        this.o_pc.addStream(__o_media_stream_video);

        //this.o_mgr.set_stream_local(__o_media_stream_video);
    } else {
        //this.o_pc.addStream(__o_media_stream_video_min);
        //this.o_pc.removeStream(this.o_local_stream);
        this.o_pc.removeStream(__o_media_stream_video_min);
        this.o_pc.removeStream(__o_media_stream_video);
        this.o_local_stream = __o_media_stream_video_min;
        //this.o_pc.addStream(__o_media_stream_video);
        this.o_pc.addStream(__o_media_stream_video_min);
        //this.o_mgr.set_stream_local(__o_media_stream_video_min);
    }
}

tmedia_session_jsep.prototype.setLocalUserMedia = function (o_stream) {
    var This = this;
    if (This && This.o_pc && This.o_mgr) {
        if(!o_stream.videoTracks || !o_stream.audioTracks){
            var b_support_audio = !!(This.e_type.i_id & tmedia_type_e.AUDIO.i_id);
            var b_support_video = !!(This.e_type.i_id & tmedia_type_e.VIDEO.i_id);
            o_stream.audioTracks = o_stream.getAudioTracks ? o_stream.getAudioTracks() : {length: b_support_audio ? 1 : 0};
            o_stream.videoTracks = o_stream.getVideoTracks ? o_stream.getVideoTracks() : {length: b_support_video ? 1 : 0};
        }

        //This.o_pc.removeStream(This.o_local_stream);
        //This.o_local_stream.stop();
        //This.o_local_stream = null;

        This.o_local_stream = o_stream;
        This.o_pc.addStream(o_stream);
        This.o_mgr.set_stream_local(o_stream);

        //This.o_local_stream = This.o_mgr.o_stream_remote;
        //This.o_pc.addStream(This.o_mgr.o_stream_remote);
        //This.o_mgr.set_stream_local(This.o_mgr.o_stream_remote);


        //navigator.getUserMedia(media_constraints, function(o_stream){ This.media_successCallback(o_stream, This); }, This.media_errorCallback);

        //This.decorate_lo(true);
        //This.__start();

    }
}

//
//  JSEP01
//

function tmedia_session_jsep01(o_mgr) {
    tmedia_session_jsep.call(this, o_mgr);
    this.o_media_constraints =
        { 'mandatory':
                {
                    'OfferToReceiveAudio': !!(this.e_type.i_id & tmedia_type_e.AUDIO.i_id),
                    'OfferToReceiveVideo': !!(this.e_type.i_id & tmedia_type_e.VIDEO.i_id)
                },
            'optional':
                [
                    {DtlsSrtpKeyAgreement: true}
                ]
        };

    if (o_mgr.s_source_id) {
        this.s_screenShareId = o_mgr.s_source_id;
    }
    if (o_mgr.s_source_stream) {
        this.s_screenStream = o_mgr.s_source_stream;
    }

    if(tsk_utils_get_navigator_friendly_name() == 'firefox'){
        tmedia_session_jsep01.mozThis = this;
        this.o_media_constraints.mandatory.MozDontOfferDataChannel = true;
    }
}

tmedia_session_jsep01.mozThis = undefined;

tmedia_session_jsep01.onGetUserMediaSuccess = function (o_stream, _This) {
    tsk_utils_log_info("onGetUserMediaSuccess");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (This && This.o_pc && This.o_mgr) {
        if(!This.b_sdp_lo_pending){
            tsk_utils_log_warn("onGetUserMediaSuccess but no local sdp request is pending");
            return;
        }

        if (o_stream) {
            // save stream other next calls
            if (o_stream.getAudioTracks().length > 0 && o_stream.getVideoTracks().length == 0) {
                __o_jsep_stream_audio = o_stream;
            } else if (o_stream.getAudioTracks().length > 0 && o_stream.getVideoTracks().length > 0) {
                __o_jsep_stream_audiovideo = o_stream;
            } else if (o_stream.getAudioTracks().length == 0 && o_stream.getVideoTracks().length > 0) {
                if (This.b_stream_max) {
                    if (!__o_media_stream_video) {
                        tsk_utils_log_info("add max video media stream....");
                        //__o_media_stream_video = o_stream;
                    }
                } else {
                    if (!__o_media_stream_video_min) {
                        tsk_utils_log_info("add min video media stream....");
                        //__o_media_stream_video_min = o_stream;
                    }
                }
            }

            if (!This.o_local_stream) {
                This.o_mgr.callback(tmedia_session_events_e.STREAM_LOCAL_ACCEPTED, this.e_type);
            }

            // HACK: Firefox only allows to call gum one time
            if (tmedia_session_jsep01.mozThis) {
                __o_jsep_stream_audiovideo = __o_jsep_stream_audio = o_stream;
            }

            This.o_local_stream = o_stream;
            This.o_pc.addStream(o_stream);

        }
        else {
            tsk_utils_log_warn("onGetUserMediaSuccess: stream is null.");
            // Probably call held
        }

        //This.o_pc.addStream(__o_media_stream_video_min);
        //This.o_pc.addStream(__o_media_stream_video);
        This.o_mgr.set_stream_local(o_stream);
        //This.o_pc.removeStream(__o_media_stream_video_min);

        if ( tsk_mcs_type_is_rnapp() && !This.o_pc_sdp ) {
            tsk_utils_log_info("onGetUserMediaSuccess EXIT.");
            //This.o_pc.createOffer(
            //    function(o_offer){ tmedia_session_jsep01.onCreateSdpSuccess(o_offer, This);},
            //    function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); }
            //);
            return;
        }

        var b_answer = ((This.b_sdp_ro_pending || This.b_sdp_ro_offer) && (This.o_sdp_ro != null));
        if (b_answer) {
            tsk_utils_log_info("createAnswer");
            This.o_pc.createAnswer(
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpSuccess : function(o_offer){ tmedia_session_jsep01.onCreateSdpSuccess(o_offer, This); },
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpError : function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); },
                This.o_media_constraints,
                false // createProvisionalAnswer
            );
        }
        else {
            tsk_utils_log_info("createOffer");
            This.o_pc.createOffer(
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpSuccess : function(o_offer){ tmedia_session_jsep01.onCreateSdpSuccess(o_offer, This); },
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpError : function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); },
                This.o_media_constraints
            );
        }
    }
}

tmedia_session_jsep01.onGetUserMediaRecvonly = function ( _This) {
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (This && This.o_pc && This.o_mgr) {
        if(!This.b_sdp_lo_pending){
            tsk_utils_log_warn("onGetUserMediaRecvonly but no local sdp request is pending");
            return;
        }
        var b_answer = ((This.b_sdp_ro_pending || This.b_sdp_ro_offer) && (This.o_sdp_ro != null));
        if (b_answer) {
            tsk_utils_log_info("createAnswer");
            This.o_pc.createAnswer(
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpSuccess : function(o_offer){ tmedia_session_jsep01.onCreateSdpSuccess(o_offer, This); },
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpError : function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); },
                This.o_media_constraints,
                false // createProvisionalAnswer
            );
        }
        else {
            tsk_utils_log_info("createOffer");
            This.o_pc.createOffer(
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpSuccess : function(o_offer){ tmedia_session_jsep01.onCreateSdpSuccess(o_offer, This); },
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onCreateSdpError : function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); },
                This.o_media_constraints
            );
        }
    }
}

tmedia_session_jsep01.onGetUserMediaError = function (s_error, _This) {
    tsk_utils_log_info("onGetUserMediaError");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (This && This.o_mgr) {
        tsk_utils_log_error(s_error);
        This.b_lo_held = false;
        This.b_ro_held = true;
        tsk_utils_log_info("onGetUserMediaError lo_held:"+This.b_lo_held+" ro_held:"+This.b_ro_held);
        if (tmedia_session_jsep01.mozThis) {
            tmedia_session_jsep01.onGetUserMediaRecvonly();
        } else {
            tmedia_session_jsep01.onGetUserMediaRecvonly(This);
        }
        //This.o_mgr.callback(tmedia_session_events_e.STREAM_LOCAL_REFUSED, This.e_type);
    }
}

tmedia_session_jsep01.onCreateSdpSuccess = function (o_sdp, _This) {
    tsk_utils_log_info("onCreateSdpSuccess");
    var This = (tmedia_session_jsep01.mozThis || _This);

    This.o_pc_sdp = o_sdp;
    if (This && This.o_pc) {
        if ( 0 && Platform && Platform.OS && Platform.OS === 'ios' &&
            o_sdp && o_sdp.sdp && o_sdp.sdp.indexOf("group:BUNDLE") == -1) {
            var s_sdp = o_sdp.sdp;
            var tIndex = s_sdp.indexOf("t=0 0\r\n");
            if (tIndex != -1) {
                o_sdp.sdp = s_sdp.substring(0, tIndex+7) + "a=group:BUNDLE audio video\r\n" + s_sdp.substring(tIndex+7);
            } else {
                o_sdp.sdp = "a=group:BUNDLE audio video\r\n" + s_sdp;
            }
        }
        This.o_pc.setLocalDescription(o_sdp,
            tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onSetLocalDescriptionSuccess : function(){ tmedia_session_jsep01.onSetLocalDescriptionSuccess(This); },
            tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onSetLocalDescriptionError : function(s_error){ tmedia_session_jsep01.onSetLocalDescriptionError(s_error, This); }
        );
        if(tmedia_session_jsep01.mozThis && !tmedia_session_jsep01.mozThis.localDescription){
            tmedia_session_jsep01.mozThis.localDescription = o_sdp; // HACK: Firefox Nightly 20.0a1 => "PeeConnection.localDescription" always undefined or not correct. More info at https://bugzilla.mozilla.org/show_bug.cgi?id=828235
        }
    }
}

tmedia_session_jsep01.onCreateSdpError = function (s_error, _This) {
    tsk_utils_log_info("onCreateSdpError");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (This && This.o_mgr) {
        tsk_utils_log_error(s_error);
        This.o_mgr.callback(tmedia_session_events_e.GET_LO_FAILED, This.e_type);
    }
}

tmedia_session_jsep01.onSetLocalDescriptionSuccess = function(_This){
    tsk_utils_log_info("onSetLocalDescriptionSuccess");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (This && This.o_pc) {
        /*if (This.o_pc.localDescription) {
            tsk_utils_log_info("onSetLocalDescriptionSuccess: setRemoteDescription");
            This.o_pc.setRemoteDescription(new RTCSessionDescription(This.o_pc.localDescription), function () {
                tsk_utils_log_info("setRemoteDescription: success.");
            }, function () {
                tsk_utils_log_info("setRemoteDescription: error.");
            });
        }*/
        tsk_utils_log_info("onSetLocalDescriptionSuccess iceGatheringState: "+This.o_pc.iceGatheringState);
        if ((This.o_pc.iceGatheringState || This.o_pc.iceState) === "complete") {
            This.bAnswerCompleted = true;
            this.b_sdp_lo_pending = true;
            tmedia_session_jsep01.onIceGatheringCompleted(This);
            This.b_sdp_ro_offer = false; // reset until next incoming RO
        }
    }
}

tmedia_session_jsep01.onSetLocalDescriptionError = function(s_error, _This){
    tsk_utils_log_info("onSetLocalDescriptionError");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (This && This.o_mgr) {
        tsk_utils_log_error("onSetLocalDescriptionError: "+JSON.stringify(s_error));
        This.o_mgr.callback(tmedia_session_events_e.GET_LO_FAILED, This.e_type);
    }
}

tmedia_session_jsep01.onSetRemoteDescriptionSuccess = function(_This){
    tsk_utils_log_info("onSetRemoteDescriptionSuccess");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if(This){
        if (!This.b_sdp_ro_pending && This.b_sdp_ro_offer) {
            tsk_utils_log_info("set remote set sdp lo null.");
            //This.o_sdp_lo = null; // to force new SDP when get_lo() is called
        }
    }
}

tmedia_session_jsep01.onSetRemoteDescriptionError = function(s_error, _This){
    tsk_utils_log_info("onSetRemoteDescriptionError");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if(This){
        This.o_mgr.callback(tmedia_session_events_e.SET_RO_FAILED, This.e_type);
        tsk_utils_log_error("set remote sdp error: "+s_error&&s_error.message? s_error.message:JSON.stringify(s_error));
    }
}

tmedia_session_jsep01.onIceGatheringCompleted = function (_This) {
    tsk_utils_log_info("onIceGatheringCompleted");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if(This && This.o_pc){
        if (!This.iIceTimerId) {
            clearTimeout(This.iIceTimerId);
            This.iIceTimerId = null;
        }

        if(!This.b_sdp_lo_pending){
            tsk_utils_log_warn("onIceGatheringCompleted but no local sdp request is pending");
            return;
        }
        This.b_sdp_lo_pending = false;
        // HACK: Firefox Nightly 20.0a1(2013-01-08): PeerConnection.localDescription has a wrong value (remote sdp). More info at https://bugzilla.mozilla.org/show_bug.cgi?id=828235
        var localDescription = (This.localDescription || This.o_pc.localDescription);
        if(localDescription){
            This.o_sdp_jsep_lo = localDescription;
            This.o_sdp_lo = tsdp_message.prototype.Parse(This.o_sdp_jsep_lo.sdp);
            tsk_utils_log_info("onIceGatheringCompleted: decorate_lo");
            This.decorate_lo(true);

            if (0 && Platform && Platform.OS && Platform.OS === 'ios' && This.e_type == tmedia_type_e.AUDIO) {
                tsk_utils_log_info("onIceGatheringCompleted: save audio.");
                oAudioMediaSession = This;
                return;
            }
            if (This.o_mgr) {
                This.o_mgr.callback(tmedia_session_events_e.GET_LO_SUCCESS, This.e_type);
            }
        }
        else{
            This.o_mgr.callback(tmedia_session_events_e.GET_LO_FAILED, This.e_type);
            tsk_utils_log_error("localDescription is null");
        }
    }
}


tmedia_session_jsep01.onIceCandidate = function (o_event, _This) {
    var This = (tmedia_session_jsep01.mozThis || _This);
    if(!This || !This.o_pc){
        tsk_utils_log_error("This/PeerConnection is null: unexpected");
        return;
    }

    tsk_utils_log_info("onIceCandidate: iceGatheringState: "+This.o_pc.iceGatheringState);

    function onIceTimeout() {
        tsk_utils_log_warn("onIceCandidate: ICE TimeOut.");
        This.sIceState = "complete";
        This.sIceState = null;
        This.iIceTimerId = null;
        //This.o_pc.iceState = "complete";
        This.iTypHost = 0;
        This.iTcpSum = 0;
        tmedia_session_jsep01.onIceGatheringCompleted(This);
    }

    var iceState = (This.o_pc.iceGatheringState || This.o_pc.iceState);
    if (This.o_pc.iceState === "complete") {
        tsk_utils_log_info("onIceCandidate iceState === complete");
        return;
    }

    if (!This.sIceState) {
        /*
        This.sIceState = "connecting";
        This.iIceTimerId = setTimeout(function () {
            tsk_utils_log_warn("onIceCandidate: ICE TimeOut.");
            This.sIceState = "complete";
            This.sIceState = null;
            This.iIceTimerId = null;
            This.o_pc.iceState = "complete";
            This.iTypHost = 0;
            This.iTcpSum = 0;
            tmedia_session_jsep01.onIceGatheringCompleted(This);
        }, 3000);*/
    }

    if (tsk_mcs_type_is_rnapp() || tsk_mcs_type_is_pcapp()) {
        if (o_event && o_event.candidate && o_event.candidate.candidate) {

            //var n_index = o_event.candidate.candidate.indexOf(" ufrag");
            //if (n_index != -1) {
            //    o_event.candidate.candidate = o_event.candidate.candidate.substring(0, n_index);
            //}
            if (o_event.candidate.candidate.indexOf(" tcp ") == -1 && o_event.candidate.candidate.split(":").length < 3) {

                tsk_utils_log_info("onIceCandidate add "+o_event.candidate.sdpMid+" candidate : "+o_event.candidate.candidate);

                if (o_event.candidate && o_event.candidate.sdpMid == "video") {
                    This.arrVideoCandidata.push(o_event.candidate);
                } else if (o_event.candidate && o_event.candidate.sdpMid == "audio") {
                    This.arrAudioCandidata.push(o_event.candidate);
                }
            }
        }
        if (This.iIceTimerId) {
            clearTimeout(This.iIceTimerId);
            This.iIceTimerId = null;
        }
        if (!This.iIceTimerId) {
            This.iIceTimerId = setTimeout(function () {onIceTimeout();}, 10000);
        }

        //return;
    }

    if (o_event && o_event.candidate && o_event.candidate.candidate) {
        tsk_utils_log_info("onIceCandidate: "+o_event.candidate.candidate);
        if (o_event.candidate.candidate.indexOf(" udp ")!=-1) {
            if (o_event.candidate.candidate.indexOf(" typ host ")!=-1) {
                This.iTypHost++;
            }
        } else {
            This.iTcpSum++;
            if (This.iTcpSum == This.iTypHost) {
                tsk_utils_log_info("ICE candedate tcp date complete.");
                iceState = "complete";
            }
        }
    }

    if (iceState === "complete" || (o_event && !o_event.candidate)
        || This.sIceState == "complete"/* || (o_event.candidate.candidate.indexOf(" udp ")!=-1)*/) {
        This.sIceState = null;
        if (This.iIceTimerId) {
            clearTimeout(This.iIceTimerId);
        }
        This.iIceTimerId = null;
        This.o_pc.iceState = "complete";
        This.iTypHost = 0;
        This.iTcpSum = 0;
        tsk_utils_log_info("ICE GATHERING COMPLETED!");
        tmedia_session_jsep01.onIceGatheringCompleted(This);
    }
    else if (This.o_pc.iceState === "failed") {
        tsk_utils_log_error("Ice state is 'failed'");
        This.o_mgr.callback(tmedia_session_events_e.GET_LO_FAILED, This.e_type);
    }
}

tmedia_session_jsep01.onIceConnectionStateChange = function(o_event, _This) {
    tsk_utils_log_info("onIceConnectionStateChange");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (!This || !This.o_pc) {
        // do not raise error: could happen after pc.close()
        return;
    }
    tsk_utils_log_warn("onIceConnectionStateChange iceGatheringState: "+This.o_pc.iceGatheringState+", iceState: "+This.o_pc.iceState+", iceConnectionState: "+This.o_pc.iceConnectionState);
}

tmedia_session_jsep01.onIceGatheringStateChange = function(o_event, _This) {
    tsk_utils_log_info("onIceGatheringStateChange");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (!This || !This.o_pc) {
        // do not raise error: could happen after pc.close()
        return;
    }
    tsk_utils_log_warn("onIceGatheringStateChange iceGatheringState: "+This.o_pc.iceGatheringState+", iceConnectionState: "+This.o_pc.iceConnectionState);
    var b_answer = ((This.b_sdp_ro_pending || This.b_sdp_ro_offer) && (This.o_sdp_ro != null));
    if (b_answer && This.o_pc.iceGatheringState == "complete" && !This.bAnswerCompleted) {
        //This.bAnswerCompleted = true;
        //tmedia_session_jsep01.onIceGatheringCompleted(This);
    }
}
tmedia_session_jsep01.onNegotiationNeeded = function(o_event, _This) {
    tsk_utils_log_info("onNegotiationNeeded");
    var This = (tmedia_session_jsep01.mozThis || _This);
    if (!This || !This.o_pc) {
        // do not raise error: could happen after pc.close()
        return;
    }

    if ((This.o_pc.iceGatheringState || This.o_pc.iceState) !== "new") {
        tmedia_session_jsep01.onGetUserMediaSuccess(This.b_lo_held ? null : This.o_local_stream, This);
    }
}

tmedia_session_jsep01.onSignalingstateChange = function (o_event, _This) {
    var This = (tmedia_session_jsep01.mozThis || _This);
    if(!This || !This.o_pc){
        // do not raise error: could happen after pc.close()
        return;
    }
    tsk_utils_log_info("onSignalingstateChange:" + This.o_pc.signalingState);
    if (This.o_local_stream && This.o_pc.signalingState === "have-remote-offer") {
        tmedia_session_jsep01.onGetUserMediaSuccess(This.o_local_stream, This);
    }
}


tmedia_session_jsep01.prototype.__get_lo = function () {
    var This = this;

    if (!this.o_pc/* && !this.b_lo_held*/) {
        var videoId = "";
        var audioId = "";
        if ( !tsk_mcs_type_is_rnapp() ) {
            var videoId = window.localStorage.getItem('org.doubango.expert.cameraId');
            var audioId = window.localStorage.getItem('org.doubango.expert.audioId');
        }
        var o_video_constraints = {
            mandatory: { },
            optional: [{sourceId: videoId}]
        };
        var o_audio_constraints = {optional: [{sourceId: audioId}]};

        if((this.e_type.i_id & tmedia_type_e.SCREEN_SHARE.i_id) == tmedia_type_e.SCREEN_SHARE.i_id) {
            o_video_constraints.mandatory.chromeMediaSource = 'screen';
        }
        if(this.e_type.i_id & tmedia_type_e.VIDEO.i_id) {
            if(this.o_video_size) {
                if(this.o_video_size.minWidth) o_video_constraints.mandatory.minWidth = this.o_video_size.minWidth;
                if(this.o_video_size.minHeight) o_video_constraints.mandatory.minHeight = this.o_video_size.minHeight;
                if(this.o_video_size.maxWidth) o_video_constraints.mandatory.maxWidth = this.o_video_size.maxWidth;
                if(this.o_video_size.maxHeight) o_video_constraints.mandatory.maxHeight = this.o_video_size.maxHeight;
            }
            if (this.o_video_framerate) {
                if (this.o_video_framerate.minFrameRate) o_video_constraints.mandatory.minFrameRate = this.o_video_framerate.minFrameRate;
                if (this.o_video_framerate.maxFrameRate) o_video_constraints.mandatory.maxFrameRate = this.o_video_framerate.maxFrameRate;
            }
            if (((this.e_type.i_id & tmedia_type_e.SCREEN_SHARE.i_id) == tmedia_type_e.SCREEN_SHARE.i_id) && this.s_screenShareId) {
                tsk_utils_log_info(">>> media session jsep source id: "+this.s_screenShareId);
                o_video_constraints.mandatory.chromeMediaSource = 'desktop';
                o_video_constraints.mandatory.chromeMediaSourceId = this.s_screenShareId;
            }
            try{ tsk_utils_log_info("Video Contraints:" + JSON.stringify(o_video_constraints)); } catch(e){}
        }
        this.ao_ice_servers = [{url: 'stun:192.168.78.250:3478'}];
        var o_iceServers = this.ao_ice_servers;
        if(!o_iceServers){ // defines default ICE servers only if none exist (because WebRTC requires ICE)
            // HACK Nightly 21.0a1 (2013-02-18):
            // - In RTCConfiguration passed to RTCPeerConnection constructor: FQDN not yet implemented (only IP-#s). Omitting "stun:stun.l.google.com:19302"
            // - CHANGE-REQUEST not supported when using "numb.viagenie.ca"
            // - (stun/ERR) Missing XOR-MAPPED-ADDRESS when using "stun.l.google.com"
            // numb.viagenie.ca: 66.228.45.110:
            // stun.l.google.com: 173.194.78.127
            // stun.counterpath.net: 216.93.246.18
            // "23.21.150.121" is the default STUN server used in Nightly
            o_iceServers = tmedia_session_jsep01.mozThis
                ? [{ url: 'stun:23.21.150.121:3478'}, { url: 'stun:216.93.246.18:3478'}, { url: 'stun:66.228.45.110:3478'}, { url: 'stun:173.194.78.127:19302'}]
                : [{ url: 'stun:stun.l.google.com:19302'}, { url: 'stun:stun.counterpath.net:3478'}, { url: 'stun:numb.viagenie.ca:3478'}];
        }
        try{ tsk_utils_log_info("ICE servers:" + JSON.stringify(o_iceServers)); } catch(e){}
        if (Platform && Platform.OS && RTCPeerConnection) {
            this.o_pc = new RTCPeerConnection(pc_configuration);
        } else {
            this.o_pc = new window.RTCPeerConnection (
                (o_iceServers && !o_iceServers.length) ? null : { iceServers: o_iceServers }/*, bundlePolicy: "balanced"*/, // empty array is used to disable STUN/TURN.
                this.o_media_constraints
            );
        }

        if ( tsk_mcs_type_is_rnapp() && !This.o_pc_sdp ) {

            this.o_pc.onnegotiationneeded = function () {
                tsk_utils_log_info("onnegotiationneeded: "+This.e_type.s_name);

                var oSdpOptions = {};

                if (This.e_type == tmedia_type_e.AUDIO) {
                    oSdpOptions = {
                        mandatory: {
                            OfferToReceiveAudio: true,
                            OfferToReceiveVideo: false,
                        },
                        optional: [],
                    };
                } else if (This.e_type == tmedia_type_e.AUDIO_VIDEO) {
                    oSdpOptions = {
                        mandatory: {
                            OfferToReceiveAudio: true,
                            OfferToReceiveVideo: true,
                            googUseRtpMUX: false,
                        },
                        optional: [],
                    };
                }

                if (This && This.o_pc/* && !This.o_pc_sdp*/) {
                    var b_answer = ((This.b_sdp_ro_pending || This.b_sdp_ro_offer) && (This.o_sdp_ro != null));
                    if (b_answer) {
                        tsk_utils_log_info("rn createAnswer");
                        This.o_pc.createAnswer(
                            function(o_answer){ tmedia_session_jsep01.onCreateSdpSuccess(o_answer, This);},
                            function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); },
                            oSdpOptions
                        );
                    } else {
                        tsk_utils_log_info("rn createOffer");
                        This.o_pc.createOffer(
                            function(o_offer){ tmedia_session_jsep01.onCreateSdpSuccess(o_offer, This);},
                            function(s_error){ tmedia_session_jsep01.onCreateSdpError(s_error, This); },
                            oSdpOptions
                        );
                    }

                }

            };
        } else {
            this.o_pc.onnegotiationneeded = tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onNegotiationNeeded : function (o_event) { tmedia_session_jsep01.onNegotiationNeeded(o_event, This); };
        }

        this.o_pc.onicecandidate = tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onIceCandidate : function(o_event){ tmedia_session_jsep01.onIceCandidate(o_event, This); };
        this.o_pc.oniceconnectionstatechange = tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onIceConnectionStateChange : function(o_event){ tmedia_session_jsep01.onIceConnectionStateChange(o_event, This); };
        this.o_pc.onicegatheringstatechange = tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onIceGatheringStateChange : function(o_event){ tmedia_session_jsep01.onIceGatheringStateChange(o_event, This); };

        this.o_pc.onsignalingstatechange = tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onSignalingstateChange : function (o_event) { tmedia_session_jsep01.onSignalingstateChange(o_event, This); };

        this.subscribe_stream_events();
    }

    if (!this.o_sdp_lo && !this.b_sdp_lo_pending) {
        this.b_sdp_lo_pending = true;
        //this.b_stream_max = false;
        // set penfing ro if there is one
        if (this.b_sdp_ro_pending && this.o_sdp_ro) {
            this.__set_ro(this.o_sdp_ro, true);
        }
        // get media stream
        if(this.e_type == tmedia_type_e.AUDIO && (this.b_cache_stream && __o_jsep_stream_audio)){
            tmedia_session_jsep01.onGetUserMediaSuccess(__o_jsep_stream_audio, This);
        }
        else if(this.e_type == tmedia_type_e.AUDIO_VIDEO && (this.b_cache_stream && __o_jsep_stream_audiovideo)){
            tmedia_session_jsep01.onGetUserMediaSuccess(__o_jsep_stream_audiovideo, This);
        }
        else if (this.e_type == tmedia_type_e.VIDEO &&
            ((this.b_stream_max && __o_media_stream_video) || (!this.b_stream_max && __o_media_stream_video_min))) {
            if (this.b_stream_max) {
                tsk_utils_log_info("use max video media stream....");
                tmedia_session_jsep01.onGetUserMediaSuccess(__o_media_stream_video, This);
            } else {
                tsk_utils_log_info("use min video media stream....");
                tmedia_session_jsep01.onGetUserMediaSuccess(__o_media_stream_video_min, This);
            }
        }
        else{
            this.o_mgr.callback(tmedia_session_events_e.STREAM_LOCAL_REQUESTED, this.e_type);
            if (this.s_screenStream) {
                tsk_utils_log_info("___>>> screen stream not null");
                if (tmedia_session_jsep01.mozThis) {
                    tmedia_session_jsep01.onGetUserMediaSuccess(this.s_screenStream);
                } else {
                    tmedia_session_jsep01.onGetUserMediaSuccess(this.s_screenStream, This);
                }
            } else {
                tsk_utils_log_info("___>>> media stream lo: "+this.b_lo_held+", ro: "+this.b_ro_held);
                if (!this.b_lo_held && this.b_ro_held) {
                    if (tmedia_session_jsep01.mozThis) {
                        tmedia_session_jsep01.onGetUserMediaRecvonly();
                    } else {
                        tmedia_session_jsep01.onGetUserMediaRecvonly(This);
                    }
                } else {
                    tsk_utils_log_warn("___>>> get user media type: "+this.e_type.s_name);
                    if (Platform && Platform.OS && getUserMedia) {
                        // set video is front
                        phoneVideoIsFront = true;
                        var oMediaConfigure = getMediaConfigureInfo(
                            this.e_type == tmedia_type_e.AUDIO? false:true,
                            this.e_type == tmedia_type_e.VIDEO? false:true
                        );
                        if (this.e_type == tmedia_type_e.AUDIO_VIDEO) {
                            oMediaConfigure = getMediaConfigureInfo(false, false);
                        }

                        getUserMedia(oMediaConfigure,
                            function(o_stream){ tmedia_session_jsep01.onGetUserMediaSuccess(o_stream, This); },
                            function(s_error){ tmedia_session_jsep01.onGetUserMediaError(s_error, This); }
                        );

                    } else {
                        var oMediaConfigure = { audio: true,
                            video: {
                                mandatory: {
                                    minWidth: 640,
                                    minHeight: 480,
                                    maxWidth: 640,
                                    maxHeight: 480,
                                    minFrameRate: 25,
                                }
                            }
                        };
                        getUserMedia(
                            oMediaConfigure,
                            tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onGetUserMediaSuccess : function(o_stream){ tmedia_session_jsep01.onGetUserMediaSuccess(o_stream, This); },
                            tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onGetUserMediaError : function(s_error){ tmedia_session_jsep01.onGetUserMediaError(s_error, This); }
                        );
                    }
                }
            }
        }
    }

    return this.o_sdp_lo;
}

tmedia_session_jsep01.prototype.__set_ro = function (o_sdp, b_is_offer) {
    if (!o_sdp) {
        tsk_utils_log_error("Invalid argument");
        return -1;
    }

    //tsk_utils_log_info("meida set remote: "+JSON.stringify(o_sdp));
    tsk_utils_log_info("meida set remote type: "+b_is_offer);
    /* update remote offer */
    this.o_sdp_ro = o_sdp;
    this.b_sdp_ro_offer = b_is_offer;

    if (this.o_pc) {
        try {
            var This = this;
            this.decorate_ro(false);
            //b_is_offer = false;

            if (0 && Platform && Platform.OS /*&& Platform.OS === 'ios'*/ ) {
                if (This.recvAudioCandidata.length > 0) {
                    for (var i=0; i<This.recvAudioCandidata.length; i++) {
                        if (This.recvAudioCandidata[i] && This.recvAudioCandidata[i].candidate) {
                            tsk_utils_log_info("addIceCandidate audio: "+This.recvAudioCandidata[i].candidate);
                            This.o_pc.addIceCandidate(new RTCIceCandidate(This.recvAudioCandidata[i]),
                                function() {
                                    tsk_utils_log_info("addIceCandidate audio success.");
                                },
                                function () {
                                    tsk_utils_log_warn("addIceCandidate audio failed.");
                                }
                            );

                        }
                    }
                    This.recvAudioCandidata.splice(0, This.recvAudioCandidata.length);
                }

                if (This.recvVideoCandidata.length > 0) {
                    for (var i=0; i<This.recvVideoCandidata.length; i++) {
                        if (This.recvVideoCandidata[i] && This.recvVideoCandidata[i].candidate) {
                            tsk_utils_log_info("addIceCandidate: "+This.recvVideoCandidata[i].candidate);
                            This.o_pc.addIceCandidate(new RTCIceCandidate(This.recvVideoCandidata[i]),
                                function() {
                                    tsk_utils_log_info("addIceCandidate success.");
                                },
                                function () {
                                    tsk_utils_log_warn("addIceCandidate failed: ");
                                }
                            );

                        }
                    }
                    This.recvVideoCandidata.splice(0, This.recvVideoCandidata.length);
                }
            }

            //tsk_utils_log_info("setRemoteDescription(" + (b_is_offer ? "offer)" : "answer)") + "\n" + this.o_sdp_ro);
            tsk_utils_log_info("setRemoteDescription(" + (b_is_offer ? "offer)" : "answer)"));
            this.o_pc.setRemoteDescription(
                new RTCSessionDescription({ type: b_is_offer ? "offer" : "answer", sdp : This.o_sdp_ro.toString() }),
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onSetRemoteDescriptionSuccess : function() { tmedia_session_jsep01.onSetRemoteDescriptionSuccess(This); },
                tmedia_session_jsep01.mozThis ? tmedia_session_jsep01.onSetRemoteDescriptionError : function(s_error) { tmedia_session_jsep01.onSetRemoteDescriptionError(s_error, This); }
            );
        }
        catch (e) {
            tsk_utils_log_error(e);
            this.o_mgr.callback(tmedia_session_events_e.SET_RO_FAILED, this.e_type);
            return -2;
        }
        finally {
            this.b_sdp_ro_pending = false;
        }
    }
    else {
        this.b_sdp_ro_pending = true;
    }

    return 0;
}

