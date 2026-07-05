"""_ml_context: bare 'transformers'/'adversarial' no longer fake ML context. [r3 B3]"""
from medusa.scanners._ml_context import has_ml_context


def test_bare_transformers_adversarial_not_ml():
    # black-style: its own AST "transformers", the bare word "adversarial"
    assert not has_ml_context("class StringTransformer:\n    transformers = []\n    self.transformers.append(x)\n")
    assert not has_ml_context("# handle adversarial input from users\nresult = adversarial_flag or False\n")


def test_real_ml_still_gates_in():
    # HF import forms + usage that real ML code carries
    assert has_ml_context("import transformers\nm = transformers.pipeline('x')\n")
    assert has_ml_context("from transformers import AutoModel\n")
    assert has_ml_context("model = AutoModel.from_pretrained('bert-base')\n")
    assert has_ml_context("import torch\nimport torch.nn as nn\n")
    assert has_ml_context("client = openai.OpenAI()\nclient.chat.completions.create(...)\n")
    # adversarial-ML with a real noun still counts
    assert has_ml_context("Defend against adversarial examples on the classifier.\n")
    assert has_ml_context("adversarial-training loop for robustness\n")
