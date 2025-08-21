# WP Diagnose (v1.0)

**WP Diagnose** is a single-file diagnostic and maintenance tool designed for quick intervention in emergency situations where your WordPress site is locked, giving errors, or you can't access your admin panel. It is not a plugin and should not be kept on your server permanently.

## How to Use

1.  Upload the `wp-diagnose.php` file to your server's root directory (the main folder where WordPress is installed).
2.  Navigate to `yoursite.com/wp-diagnose.php` in your browser.
3.  You will see a detailed diagnostic report for your site. You can perform necessary actions (clearing cache, deactivating plugins, etc.) from the Tools section.

## ⚠️ **IMPORTANT SECURITY WARNING**

This tool has the ability to change the most sensitive settings of a site and is a serious security risk as it runs directly in the server's root directory.

* **After you are done, you must immediately delete this file from your server.**
* WP Diagnose includes a security mechanism to automatically delete itself after 60 minutes. However, this mechanism may fail in some server configurations. Therefore, **manually deleting it is always the safest approach.**

## ⚙️ **Notes on `wp-content/mu-plugins`**

Through the **"Sitemap Force ON"** button in the "Tools" section, WP Diagnose creates a temporary file named **`force-sitemaps.php`** inside the `wp-content/mu-plugins` folder to enable WordPress's native sitemap feature.

* **How it Works:** `mu-plugins` (Must-Use Plugins) are automatically enabled by WordPress and cannot be disabled from the admin panel. Therefore, the `force-sitemaps.php` file ensures your site's sitemap feature remains active at all times.
* **To Prevent Conflicts:** Leaving this temporary file on your server could lead to conflicts with other sitemap plugins in the future or make it impossible to change your sitemap settings from within WordPress.

**After you have completed your WP Diagnose session, for security and cleanup purposes, you must delete the `wp-diagnose.php` file and all files inside the `wp-content/mu-plugins` folder (especially the `force-sitemaps.php` file).**

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). See the `LICENSE` file for more details.

---

# WP Diagnose (v1.0)

**WP Diagnose**, WordPress siteniz kilitlendiğinde, hata verdiğinde veya yönetim panelinize erişemediğiniz acil durumlarda hızlı müdahale için tasarlanmış tek dosyalık bir teşhis ve bakım aracıdır. Bu bir eklenti değildir ve kalıcı olarak sunucunuzda tutulmamalıdır.

## Nasıl Kullanılır?

1.  `wp-diagnose.php` dosyasını sunucunuzun kök dizinine (WordPress'in kurulu olduğu ana klasör) yükleyin.
2.  Tarayıcınızdan `siteniz.com/wp-diagnose.php` adresine gidin.
3.  Sayfada sitenizle ilgili detaylı bir teşhis raporu göreceksiniz. Araçlar bölümünden gerekli işlemleri (önbellek temizleme, eklenti devre dışı bırakma vb.) yapabilirsiniz.

## ⚠️ **ÖNEMLİ GÜVENLİK UYARISI**

Bu araç, bir sitenin en hassas ayarlarını değiştirebilme yeteneğine sahiptir ve doğrudan sunucu kök dizininde çalıştığı için ciddi bir güvenlik riskidir.

* **İşlem bittikten sonra, bu dosyayı sunucunuzdan derhal silmelisiniz.**
* WP Diagnose, 60 dakika sonra otomatik olarak kendini silmek için bir güvenlik mekanizması içerir. Ancak, bu mekanizma bazı sunucu yapılandırmalarında başarısız olabilir. Bu nedenle **manuel olarak silmek her zaman en güvenli yaklaşımdır.**

## ⚙️ **`wp-content/mu-plugins` ile İlgili Notlar**

WP Diagnose, "Araçlar" bölümündeki **"Sitemap Force ON"** (Sitemap'i Zorla Aç) butonu aracılığıyla, WordPress'in dahili sitemap özelliğini etkinleştirmek için `wp-content/mu-plugins` klasörünün içine **`force-sitemaps.php`** adında geçici bir dosya oluşturur.

* **Çalışma Mantığı:** `mu-plugins` (Must-Use Plugins), WordPress tarafından otomatik olarak etkinleştirilen ve yönetim panelinden devre dışı bırakılamayan eklentilerdir. Bu nedenle `force-sitemaps.php` dosyası, sitenizin sitemap özelliğinin her zaman açık kalmasını sağlar.
* **Çakışmaları Önlemek İçin:** Bu geçici dosyanın sunucuda kalması, ileride başka bir sitemap eklentisiyle çakışmalara yol açabilir veya WordPress sitenizde sitemap ayarlarını değiştirmeyi imkansız hale getirebilir.

**WP Diagnose işlemini tamamladıktan sonra, güvenlik ve temizlik amacıyla `wp-diagnose.php` dosyasını sildikten sonra, `wp-content/mu-plugins` klasörünün içindeki tüm dosyaları (özellikle `force-sitemaps.php` dosyasını) da mutlaka silmelisiniz.**

## Lisans

Bu proje GNU Genel Kamu Lisansı v3.0 (GPL-3.0) altında lisanslanmıştır. Daha fazla bilgi için `LICENSE` dosyasına bakın.
