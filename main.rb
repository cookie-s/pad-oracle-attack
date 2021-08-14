def attack(ct, &try_decrypt)
  bs = 16
  blocks = ct.chars.each_slice(bs).map(&:join)

  (blocks.length-1).downto(1) do |k|
    plain = ?? * bs
    iv = "\x00" * bs

    1.upto(bs) do |n|
      256.times do |i|
        iv[-n] = i.chr
        data = iv + blocks[k]

        if try_decrypt.call(data) then
          plain = iv.bytes.zip(blocks[k-1].bytes).map{|x,y| n^x^y}.pack("C*")
          iv = plain.bytes.zip(blocks[k-1].bytes).map{|x,y| (n+1)^x^y}.pack("C*")
          break
        end
      end
    end
    p plain

    blocks[k] = plain
  end

  blocks[0] = "?" * bs
  blocks.join
end

require 'openssl'

def encrypt(data)
  c = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
  c.encrypt
  c.key = "secret".ljust(32)
  c.iv = "unknown".ljust(16)
  c.update(data) + c.final
end

def try_decrypt(data)
  c = OpenSSL::Cipher::Cipher.new('aes-256-cbc')
  c.decrypt
  c.key = "secret".ljust(32)
  c.iv = "unknown".ljust(16)
  c.update(data) + c.final rescue false
end

plain = 'In cryptography, a padding oracle attack is an attack which is performed using the padding of a cryptographic message. In cryptography, variable-length plaintext messages often have to be padded (expanded) to be compatible with the underlying cryptographic primitive. The attack relies on having a "padding oracle" who freely responds to queries about whether a message is correctly padded or not. Padding oracle attacks are mostly associated with CBC mode decryption used within block ciphers. Padding modes for asymmetric algorithms such as OAEP may also be vulnerable to padding oracle attacks.'
ciphertext = encrypt plain

p attack(ciphertext){|ct| try_decrypt ct}
