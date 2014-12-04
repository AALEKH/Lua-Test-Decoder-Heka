--[[
-- This Source Code Form is subject to the terms of the Mozilla Public
-- License, v. 2.0. If a copy of the MPL was not distributed with this
-- file, You can obtain one at http://mozilla.org/MPL/2.0/.
-- Copyright (c) 2014 Mozilla Corporation
--
-- Contributors:
-- Aalekh Nigam aalekh.nigam@gmail.com
local l = require 'lpeg'
l.locale(l)
local num = (l.digit^1 * "." * l.digit^1) / tonumber 
local name = l.R("AZ")^1*l.P("_")^-1* l.R("AZ")^0
local type = l.P("type=")*l.Cg(name,"Type")
local timestamp = l.P("msg=audit(")*l.Cg(num,"Timestamp")
local serial = l.P(":")*l.Cg(l.digit^1/tonumber,"serialnum") --Taking a integer for now

--local msgdata = l.P("):")*l.space^-1*l.Cg(l.P(1)^0,"Msgdata")


local space = l.space^0
local fieldname = l.C(l.alpha^1* (l.alnum + "-" + "_")^0)
local quoted = '"' * l.Cs(  (l.P'\\"' / '"' + (l.P(1) - '"'))^0  ) * '"'
local numeric = l.C(l.digit^1 * #l.space^1) / tonumber
local unquoted = l.C(l.alnum^1+ l.R"!~"^1)
local fieldvalue =  quoted + numeric + unquoted
local sep = space
local pair = l.Cg(fieldname * "=" * fieldvalue) * sep^-1
local tab = l.Cg(l.P("):")* space* l.Cf(l.Ct("") * pair^0, rawset),"Fields")

grammar = l.Ct(type*l.space^-1*timestamp*serial*tab)
]]--
local l = require 'lpeg'
l.locale(l)
local num = (l.digit^1 * "." * l.digit^1) / tonumber 
local name = l.R("AZ")^1*l.P("_")^-1* l.R("AZ")^0
local type = l.P("type=")*l.Cg(name,"Type")
local timestamp = l.P("msg=audit(")*l.Cg(num,"Timestamp")
local serial = l.P(":")*l.Cg(l.digit^1/tonumber,"Serialnum") --Taking a integer for now

--local msgdata = l.P("):")*l.space^-1*l.Cg(l.P(1)^0,"Msgdata")


local space = l.space^0
local fieldname = l.C(l.alpha^1* (l.alnum + "-" + "_")^0)
local quoted = '"' * l.Cs(  (l.P'\\"' / '"' + (l.P(1) - '"'))^0  ) * '"'
local numeric = l.C(l.digit^1 * #l.space^1) / tonumber
local unquoted = l.C(l.alnum^1+ l.R"!~"^1)
local fieldvalue =  quoted + numeric + unquoted
local sep = space
local pair = l.Cg(fieldname * "=" * fieldvalue) * sep^-1
local tab = l.Cg(l.P("):")* space* l.Cf(l.Ct("") * pair^0, rawset),"Fields")

grammar = l.Ct(type*l.space^-1*timestamp*serial*tab)
--local payload_keep = read_config("payload_keep")
function process_message()
    local log = read_message("Payload")

        --set a default msg that heka's
    --message matcher will ignore
    local msg = {
        Fields = {},
        Type = nil,
        Timestamp = nil,
        serialnum = nil
    }  
    local matches = grammar:match(log)
    if not matches then
        --return 0 to not propogate errors to heka's log.
        --return a message with IGNORE type to not match heka's message matcher
        if pcall(inject_message(msg)) then
            print("Success")
        else
	        print("Failure")
        end
        return 0 
    end

    -- populating our fields
    msg['Type'] = read_config('type')
    msg['Logger'] = 'heka'
    msg['Severity'] = 'INFO'
    msg.Fields['exit'] = matches[1]
    msg.Fields['euid'] = matches[2]
    msg.Fields['pid'] = matches[3]
    msg.Fields['arch'] = matches[4]
    msg.Fields['syscall'] = matches[5]
    msg.Fields['sgid'] = matches[6]
    msg.Fields['key'] = matches[7]
    msg.Fields['gid'] = matches[8]
    msg.Fields['a3'] = matches[9]
    msg.Fields['a2'] = matches[10]
    msg.Fields['a1'] = matches[11]
    msg.Fields['a0'] = matches[12]
    msg.Fields['tty'] = matches[13]
    msg.Fields['ad_adlkj'] = matches[14]
    msg.Fields['fsuid'] = matches[15]
    msg.Fields['a-ds'] = matches[16]
    msg.Fields['auid'] = matches[17]
    msg.Fields['comm'] = matches[18]
    msg.Fields['suid'] = matches[19]
    msg.Fields['items'] = matches[20]
    msg.Fields['uid'] = matches[21]
    msg.Fields['success'] = matches[22]
    msg.Fields['ses'] = matches[23]
    msg.Fields['fsgid'] = matches[24]
    msg.Fields['egid'] = matches[25]
    msg.Fields['ppid'] = matches[26]
    msg.Fields['exe'] = matches[27]
    
    
    if pcall(inject_message(msg)) then
        inject_message(msg)
        --return 0
    else
        print("Failure")
        --return 0
    end
    return 0
end
