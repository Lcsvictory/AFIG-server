from google import genai
from google.genai import types
from PIL import Image
from io import BytesIO

client = genai.Client(api_key='')

fix_prompt = ("""{menu} 메뉴로 메뉴판에 삽입할 이미지를 생성해줘.음식들은 트레이에 담겨있어. 밥의 위치는 좌측 하단이야. 국의 위치는 우측 하단이야. 그 외의 메뉴들은 상단에 배치해. 각자 그릇에 담겨있고 그 그릇들은 트레이에 담겨있는거야. 오직 트레이와 음식만 나오는 이미지로 만들어. 비율은 1:1로 만들어줘. 배경 여백은 제거하고 오직 음식 이미지만 나와야해.
""")

menus = [
    "된장찌개, 고등어구이, 김치, 밥",
    "김치찌개, 제육볶음, 계란말이, 밥",]


for menu in menus:
    response = client.models.generate_content(
        model="gemini-2.5-flash-image",
        contents=[menu+fix_prompt],
    )

for part in response.candidates[0].content.parts:
    if part.text is not None:
        print(part.text)
    elif part.inline_data is not None:
        image = Image.open(BytesIO(part.inline_data.data))
        image.save("generated_image1.png")