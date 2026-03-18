import google.generativeai as genai
from click import prompt

#import lib.utils as utils
import os
from dotenv import load_dotenv

# main
if __name__ == "__main__":
    # Load api key from .env file
    load_dotenv()
    genai.configure(api_key=os.getenv("API_KEY_GEMINI"))
    model = genai.GenerativeModel("gemini-2.5-flash")

    # Deterministic configuration
    generation_config = {
        "temperature": 0.0,     # 0.0 = sin aleatoriedad
        "top_p": 1.0,           # mantener distribución completa
        "top_k": 1,             # solo la opción más probable
        "candidate_count": 1,   # una única salida
    }

    # Loading prompt
    prompt_file="attacks/dns/prompt-only-router"
    with open(prompt_file, "r") as file:
        trace = file.readlines()
    prompt = ''.join(trace)
    print(prompt)
    response = model.generate_content(prompt, generation_config=generation_config)

    print("Model response:")
    print(response.text)
