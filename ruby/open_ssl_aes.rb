require 'openssl'
require 'securerandom'

class OpenSslAes

  attr_reader :password, :cipher

  # Initialize with the password
  def initialize(password)
    @password = password
    @cipher = OpenSSL::Cipher::Cipher.new("aes-256-cbc")
  end

  def encrypt(infile, outfile = '')
    #if outfile is an io, set binmode
    outfile.binmode if outfile.respond_to? :binmode
    infile.binmode if infile.respond_to? :binmode

    salt = generate_salt
    setup_cipher(:encrypt, salt)

    outfile << "Salted__#{salt}"

    if infile.respond_to? :read
      while chunk = infile.read(1024)
        outfile << cipher.update(chunk)
      end
    else
      outfile << cipher.update(infile)
    end

    outfile << cipher.final

    infile.close if infile.respond_to? :close
    outfile.close if outfile.respond_to? :close

    outfile
  end

  def decrypt(infile, outfile = '')
    #if files are an io, set binmode
    outfile.binmode if outfile.respond_to? :binmode
    infile.binmode if infile.respond_to? :binmode

    data = nil
    if infile.respond_to? :read
      data = infile.read(16)
    else
      data = infile[0..15]
    end

    salt = data[8..15]
    setup_cipher(:decrypt, salt)

    if infile.respond_to? :read
      while chunk = infs.read(1024)
        outfile << cipher.update(chunk)
      end
    else
      outfile << cipher.update(infile)
    end
    outfile << cipher.final

    infs.close if infile.respond_to? :close
    outfile.close if outfile.respond_to? :close

    outfile
  end

  private

  def generate_salt
    SecureRandom.random_bytes(8)
  end

  def setup_cipher(method, salt)
    cipher.send(method)
    cipher.pkcs5_keyivgen(password, salt, 1)
  end

end
