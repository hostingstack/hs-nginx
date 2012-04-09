require 'rubygems'
gem 'ffi'
require 'ffi'

class EfficientDataStruct < FFI::Struct
  layout :primary_agent_ip_strsize, :size_t,
    :primary_agent_ip_strbuf, [:char, 16],
    :secondary_agent_ip_strsize, :size_t,
    :secondary_agent_ip_strbuf, [:char, 16],
    :app_id_token_strsize, :size_t,
    :app_id_token_strbuf, [:char, 64]
end

def doit

  ds = EfficientDataStruct.new
  pri_agent = "127.127.127.127"
  sec_agent = "255.255.255.255"
  app_id_token = "424242_YADDA_TOKEN"
  if pri_agent.length > 16 or sec_agent.length > 16
    puts "pri or sec agent lengths exceed fixed size buffers"
  end
  if app_id_token.length > 64
    puts "app_id_token lengths exceed fixes size buffer"
  end
  
  ds[:primary_agent_ip_strsize] = pri_agent.length
  ds[:primary_agent_ip_strbuf].to_ptr.put_string(0, pri_agent)
  ds[:secondary_agent_ip_strsize] = sec_agent.length
  ds[:secondary_agent_ip_strbuf].to_ptr.put_string(0, sec_agent)
  ds[:app_id_token_strsize] = app_id_token.length
  ds[:app_id_token_strbuf].to_ptr.put_string(0, app_id_token)
  
  puts ds.pointer
  return ds.pointer.get_bytes(0, ds.size)
end
