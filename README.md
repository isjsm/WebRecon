# WebRecon - أداة استطلاع المواقع الالكترونية

![WebRecon Banner](https://via.placeholder.com/600x200?text=WebRecon+v2.0)

## الوصف
أداة متطورة لتحليل المواقع الإلكترونية واكتشاف الثغرات الأمنية، مصممة خصيصًا لأنظمة Kali Linux. تجمع بين تقنيات الاستطلاع المتقدمة مع واجهة مستخدم تفاعلية سهلة.

## الميزات الرئيسية
✅ **فحص كامل للموقع:**  
- اكتشاف IP والتفاصيل الأساسية
- فحص إعادة التوجيه والروابط الداخلية
- تعداد السجلات الفرعية (Subdomains)
- فحص المنافذ المفتوحة

✅ **اكتشاف الثغرات:**  
- تصنيف الثغرات (حرجة/متوسطة/منخفضة)
- فحص SQL Injection, XSS, RCE, Open Redirect
- اكتشاف الملفات الحساسة (مثل /etc/passwd)

✅ **ميزات متقدمة:**  
- دعم البروكسي
- تقرير مفصل بتنسيقات JSON و TXT
- فحص متعدد الخيوط (Multithreading)
- واجهة تفاعلية بلغة عربية

## المتطلبات
- نظام Kali Linux
- بايثون 3.8+
- حزم النظام: `python3-venv`, `pipx`

## التثبيت
```bash
# 1. تحديث النظام
sudo apt update && sudo apt upgrade -y

# 2. تثبيت المتطلبات الأساسية
sudo apt install -y python3-venv pipx

# 3. إنشاء بيئة افتراضية
python3 -m venv webrecon_env
source webrecon_env/bin/activate

# 4. تثبيت المتطلبات
pip install -r requirements.txt

# 5. إضافة صلاحيات التنفيذ
chmod +x webrecon.py

# استخدام البروكسي
python webrecon.py --proxy http://user:pass@proxy:port

# تخصيص عدد الخيوط
python webrecon.py --threads 50

# تحديد wordlists مخصصة
python webrecon.py --dir /path/to/dirs.txt --sub /path/to/subdomains.txt
