class MedusaSecurity < Formula
  include Language::Python::Virtualenv

  desc "The 42-Headed Security Guardian - Universal security scanner"
  homepage "https://pantheonsecurity.io"
  url "https://files.pythonhosted.org/packages/source/m/medusa-security/medusa_security-0.9.2.1-py3-none-any.whl"
  sha256 "NEEDS_TO_BE_CALCULATED"
  license "MIT"

  depends_on "python@3.11"

  def install
    virtualenv_install_with_resources
  end

  test do
    system "#{bin}/medusa", "--version"
  end
end
