from transformers import AutoTokenizer, AutoModelForCausalLM, pipeline

tokenizer = AutoTokenizer.from_pretrained("TinyLlama/TinyLlama-1.1B-Chat-v1.0")
model = AutoModelForCausalLM.from_pretrained("TinyLlama/TinyLlama-1.1B-Chat-v1.0", trust_remote_code=True)

chat_pipeline = pipeline("text-generation", model=model, tokenizer=tokenizer)


def get_chat_response(prompt: str) -> str:
    """
    Generates a chatbot response using TinyLlama locally.
    """
    result = chat_pipeline(
        prompt,
        max_new_tokens=200,
        temperature=0.8,
        do_sample=True,
        top_k=50,
        top_p=0.95,
    )
    return result[0]["generated_text"].replace(prompt, "").strip()

