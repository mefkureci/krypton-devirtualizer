# Krypton Devirtualizer — Notlar

## 2026-07-05 — NecroBit dump hatası bulundu ve düzeltildi

**Semptom:** `NET Reactor Unpack Me.exe` (`C:\Users\root\Desktop\.NET Reactor v7.5.9.1`)
üzerinde Krypton çalıştırıldığında üretilen `Devirtualized.exe`, `Form1..ctor()`
metodunu `nop;nop;nop;ret` (4 instr, boş) olarak bırakıyordu. Aynı hedefin
28 Haziran'da üretilmiş bir kopyası (`Devirtualized1.exe`) ise ctor'u tam ve
doğru (109 instr: TextBox/Button oluşturma, Click binding, Controls.Add)
içeriyordu.

**Kök neden:** `Krypton.Runner/NecrobitDumpRunner.cs` → `DumpHashtableBodies`,
NecroBit'in runtime hashtable'ını static field'ların **deklare edilen tipine**
bakarak arıyordu (`IDictionary.IsAssignableFrom(field.FieldType)`). Gerçek
hashtable `object` tipinde deklare edilmiş bir field'ın runtime değeriydi —
filtre onu atlıyor, alakasız 178-entry bir sabit tablosunu buluyordu (gerçek
tablo 696 entry). Sonuç: 0 method body restore ediliyordu.

İkinci bir eksiklik: `NecrobitDumpRunner.Run` sadece static/module
constructor'ları çalıştırıyordu (`RunClassConstructor`), Form1 gibi instance
constructor'lar hiç invoke edilmiyordu → NecroBit'in JIT-restore hook'u
tetiklenmiyordu.

**Düzeltme (2 değişiklik, aynı dosya):**
1. `DumpHashtableBodies`: `field.FieldType` ön-kontrolü kaldırıldı, doğrudan
   `field.GetValue(null) as IDictionary` ile runtime tipi kontrol ediliyor.
2. `Run`: `LoadAndInitialize` sonrası, hashtable dump'ından önce
   `FormSnapshot.CaptureFromEntryPoint(assembly)` çağrısı eklendi (gerçek
   entry point'i/Main'i çalıştırıp Form1'i normal akışta instantiate ediyor).

**Doğrulama:** Krypton.Runner + Krypton yeniden build edildi, tam pipeline
tekrar çalıştırıldı. Üretilen `Devirtualized.exe`'nin 1342 metodunun tamamı
`Devirtualized1.exe` ile birebir aynı (0 fark). Exe çalıştırıldı: 6+ saniye
kesintisiz, pencere açık ("Form1"/"NET Reactor Unpack Me" başlığı), çökme yok.
Şifre kontrolü (N3T_Reac benzeri) doğrulanmadı — istenmedi, önemli olan
çalışabilirlikti.

**Genel önem:** Bu, sadece bu hedefe özel değil — NecroBit korumalı HERHANGİ
bir hedefte aynı şekilde 0 method restore edilmesine yol açan genel bir araç
hatasıydı. Bkz memory `krypton-necrobit-dump-fix`.

## 2026-09-03 — Aynı hedef tekrar bozuk bulundu, 4 gerçek hata düzeltildi, 1 açık kaldı

**ÖNEMLİ:** Yukarıdaki 2026-07-05 kaydı bu hedef için Krypton'ın ÇALIŞAN bir
`Devirtualized.exe` ürettiğini gösteriyor. Bugün (2026-09-03) aynı hedefte
Krypton **hiç exe üretmiyordu** ("No methods were replaced"). Proje git deposu
DEĞİL, aradaki dönemde neyin regresyona yol açtığı bilinmiyor — muhtemelen bu
tarihten sonra eklenen heuristic'lerden biri (aşağıya bkz).

**Düzeltilen 4 gerçek hata** (`Krypton.Pipeline/Devirtualizer.cs`,
`MethodRecompiling.cs`, hepsi feature-toggle'lı KRYPTON_ENABLE_*/DISABLE_*,
varsayılan açık):

1. **Ldtoken/Ldc_I4 yapısal belirsizliği** (`MethodRecompiling.BuildLdtokenInstruction`):
   token type/field/method olarak çözülmezse artık exception atıp tüm metodu
   iptal etmek yerine `Ldc_I4` sabitine düşüyor (Ldtoken ve Ldc_I4 aynı
   pop:0/push:1/int32-operand şeklini paylaşıyor, yapısal olarak ayrılamaz).
   Sonuç: 0/8 → 8/8 metot recompile.

2. **`build-all.ps1` `Krypton.Runner`'ı hiç derlemiyor** — script'in kendisi
   düzeltilmedi, ama `dotnet build Krypton.Runner/Krypton.Runner.csproj -c
   Release` çıktısını (`Krypton.Runner.exe`+.config+dnlib.dll+0Harmony.dll+
   Newtonsoft.Json.dll) `Krypton\bin\Release\net8.0\`'a elle kopyalamak
   gerekiyor — yoksa "[HCR] Krypton.Runner.exe not found" ile NecroBit/WinForms
   payload kurtarma sessizce atlanıyor, Form1 ctor'u boş kalıyor.

3. **cctor yanlış nötrleştirme + newobj/Ldsfld yanlış eşleme**: `<Module>{guid}`
   cctor'u "işe yaramaz bootstrap" sanılıp boşaltılıyordu çünkü worker
   metodun içindeki gerçek store'u görmüyordu (`CountOwnStaticStores` artık
   1-seviye derin worker gövdesini de tarıyor). Asıl kök neden: worker metotta
   `newobj T; ldsfld <aynı tip static alan>` (yeni obje hiç saklanmadan static
   alan okunuyor) — `RepairNewobjFollowedByStaleStaticFieldRead` bunu Stsfld'e
   çeviriyor.

4. **Arithmetic-junk-before-ldfld + missing-pop**: `RepairArithmeticJunkBeforeFieldAccess`
   — `Ldfld`/`Ldflda`'dan hemen önce, sadece kendi ürettiği değerleri okuyan
   (Ldc_I4 + saf int Shl/Xor/vb.) ve net +1 derinlik bırakan bitişik komut
   dizisini siliyor (branch-target korumalı). 60 örneği düzeltti.
   `RepairMissingPopBeforeVoidReturn` — void metotta `ret`'ten hemen önce
   non-void dönüşlü Call/Newobj varsa Pop ekliyor (`MessageBox.Show(...);
   ret` deseni). 8 örneği düzeltti.

**AÇIK KALAN SORUN:** Aynı worker metotta (`method_274`, `<Module>{guid}`
içinde, module cctor'un çağırdığı) 2. bir varyant var: `ldsfld REF; ldc.i4 A;
shl (TEK sabit önden, iki değil); ldc.i4 C; shl; ldfld` — burada ilk `shl`
gerçek referansı int'miş gibi DOĞRUDAN tüketiyor, silmek yanlış olur (referans
tamamen kaybolur). En az 29 örnek var. `ilverify` `StackUnexpected`/
`ExpectedIntegerType` veriyor, runtime'da `InvalidProgramException` →
`TypeInitializationException` ile çöküyor. Sabitler mod-32'de birbirini
götürüyormuş gibi görünüyor (632250658%32=2, -632250658%32=-2) ama gerçek
no-op değil (ara sonuç her shl'de ayrı maskeleniyor). Muhtemel açıklama: VM
akışında referansı çoğaltan bir `Dup` (veya ayrı bir `ldsfld`) kayıp/yanlış
eşlenmiş — DOĞRULANMADI, tahmin. Çözüm için orijinal (VM korumalı) exe'yi
x64dbg/dnSpy ile canlı izleyip method_274'ün gerçek VM bytecode akışını
görmek gerekiyor. Kullanıcı "kaydet, sonra devam" dedi — bu oturumda ileri
gidilmedi.

**Bir sonraki oturum için ipucu:** Bugünkü karmaşıklık (arithmetic-junk,
cctor-neutralization, newobj-stsfld) 2026-07-05 notunda YOK — o zaman sadece
NecroBit dump fix'i yeterliydi. Aradaki dönemde eklenen heuristic'lerden biri
(`KRYPTON_ENABLE_REACTOR_RUNTIME_CLEANUP`, `KRYPTON_DISABLE_STARTUP_GUARD`,
`KRYPTON_NEUTRALIZE_SHARED_BOOTSTRAP`, `KRYPTON_ENABLE_TOKEN_DEOBFUSCATION_PATCH`,
`KRYPTON_ENABLE_STRICT_ANTI_MANIPULATION_PATCH` gibi) regresyona yol açmış
olabilir. Proje git deposu değil (bisect yapılamaz) — ama bu geçişleri
`KRYPTON_DISABLE_*` env değişkenleriyle TEK TEK kapatıp method_274'ün hâlâ
bozuk çıkıp çıkmadığını kontrol etmek, canlı izlemeden çok daha ucuz bir ilk
adım olur.

Build: `powershell -File build-all.ps1 -Configuration Release` (+ Runner'ı
elle kopyala, yukarı bkz). Çalıştırma: `dotnet Krypton\bin\Release\net8.0\
Krypton.dll "<hedef.exe>" --no-pause`. Doğrulama: `~/.dotnet/tools/ilverify.exe
"<Devirtualized.exe>" -r "C:\Program Files\dotnet\shared\Microsoft.NETCore.App\
*\*.dll" -r "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\*.dll"`.
Ayrıntılı analiz + memory: `krypton-ldtoken-ldc-ambiguity-fix` (auto-memory).

## 2026-09-04 — method_274 ÇÖZÜLDÜ: 8 VM byte'ı yanlış eşlenmişti

Yukarıdaki "AÇIK KALAN SORUN" kapandı. Regresyon avı (KRYPTON_DISABLE_* denemesi)
GEREKMEDİ — sorun bir heuristic regresyonu değil, baştan beri var olan bir
**opcode eşleme hatasıydı**.

**Kök neden.** `method_274`, `<Module>{guid}` yardımcı tipinin ~104 int32 alanını
obfuske sabitlerle dolduran Reactor runtime başlatıcısı. Ham VM akışındaki grup
deseni: `Ldsfld <singleton>; <sabit ifadesi>; vm:0xA0 <alan>`. Krypton `0xA0`'ı
`Ldfld` olarak eşlemişti (structural-usage, conf 0.99) — oysa **`Stfld`**. Ldfld
ile her grup yığında +1 bırakıyor, 104 grup boyunca yığın şişiyor,
`InvalidProgramException` → `TypeInitializationException` ile çöküyordu.

Ayrıca gruplardaki 7 aritmetik byte'ın TAMAMI `Shl`'e eşlenmişti (neighbor-context,
conf 0.91) — bu bytelar operandsız ve ayırt edici komşusu yok, oylama hepsini aynı
opcode'a çöktürüyor. Aritelerı bile yanlıştı (2 tanesi tekli).

**Kanıtla çözüm (tahmin değil).** İki aşamalı, tamamen belirlenmiş çıkarım:
1. **Arite**: her grup "instance yükle → ifade → alana yaz" olduğundan ifade tam 1
   değer bırakmalı. 104 grup + 7 bilinmeyen → tek çözüm.
2. **Semantik**: `Krypton.Runner --dump-fields` (parametresiz) ORİJİNAL korumalı
   exe'yi çalıştırıp o 104 alanın GERÇEK runtime değerlerini okuyor. Hangi opcode
   ataması 104 değerin hepsini birebir üretiyorsa doğrudur → yine tek çözüm.

Sonuç (aracın tahmini → gerçek): `0xA0` Ldfld→**Stfld**, `0x24` Shl→**Add**,
`0x40` Shl→**Shr**, `0x91` Shl→**Xor**, `0xAC` Shl→**Sub**, `0x1A` Shl→**Not**,
`0x25` Shl→**Neg**, `0x07` Shl→Shl (tek doğru tahmin).

**Kalıcı araç düzeltmesi** (env override DEĞİL, otomatik çalışıyor):
- Yeni: `Krypton.Pipeline/Stages/OpcodeMapping.RuntimeFieldTruth.cs` →
  `SolveOpcodesFromRuntimeFieldValues`, `ExecuteFinalizationPhase` içinde
  `ApplyEnvironmentOpcodeOverrides`'tan HEMEN ÖNCE çağrılıyor (böylece elle
  `KRYPTON_FORCE_VM_MAP` hâlâ son sözü söylüyor).
- Yeni: `Krypton.Pipeline/RunnerInvoker.cs` — Krypton.Runner başlatma mantığı
  Devirtualizer'dan çıkarılıp paylaşıldı (Devirtualizer artık buna delege ediyor).
- Kaynak adı `runtime-truth-override`: içinde "override" geçmesi BİLEREK — yoksa
  `SemanticValidation` yığın dengesizliğini görüp `0x91`'i `Nop`'a indiriyordu.
- `IndependentEvidenceSources`'a eklendi (sound-mode'da da geçerli: bu istatistik
  değil, ölçülmüş gerçek).
- Güvenlik kapıları: ≥8 grup, ≤12 bilinmeyen byte, ≤8M kombinasyon ve **çözüm
  benzersiz değilse hiçbir şey yapmıyor**. Kapatma:
  `KRYPTON_DISABLE_RUNTIME_FIELD_TRUTH_SOLVER=1`.

**Doğrulama:** env override olmadan tek geçişte "proved 7 opcode(s) against 104
observed field value(s)"; `method_274` ilverify hatası 1→**0**, dosya geneli
151→**71**; `Devirtualized.exe` çalışıyor, "Form1" penceresi açılıyor, yanıt
veriyor (2026-07-05'teki çalışan duruma dönüldü). Regresyon kontrolü: WFA37
(Reactor 6.5) hedefinde çözücü hiç tetiklenmiyor, log çıktısı
`KRYPTON_DISABLE_RUNTIME_FIELD_TRUTH_SOLVER=1` ile BİREBİR aynı.

**Not — geçmiş semptom yaması:** Önceki oturumun `RepairArithmeticJunkBeforeFieldAccess`
geçişi (60 "junk" silmişti) tam olarak BU hatayı maskeliyordu; sildiği şeyler
aslında alana yazılacak gerçek sabit hesaplarıydı. Doğru eşlemeyle artık 0 kez
tetikleniyor. Kod duruyor (feature-toggle'lı) ama şüpheli sayılmalı.

**Genel ders:** Operandsız, komşusu ayırt edici olmayan VM byte'larında istatistiksel
oylama güvenilmez — hepsini aynı opcode'a çöktürür. Ama korunan binary'nin KENDİSİ
bir oracle: gözlemlenebilir runtime durumu (alan değerleri) varsa, opcode ataması
tahmin edilecek değil ÇÖZÜLECEK bir şeye dönüşür.

## 2026-09-04 (2) — `Form1::method_23` çöküyordu: 5 opcode daha + "Ret tuzağı" araç hatası

Semptom: pencere açılıyordu ama butona basınca
`InvalidProgramException at Form1.method_23`. `ilverify` method_23'ü temiz gösteriyordu —
çünkü sorun method_23'te değil, ONA BAĞLI metotların KIRPILMIŞ olmasındaydı.

**Bulunan 5 yanlış eşleme** (hepsi ham VM akışı + çağrı imzalarıyla YAPISAL olarak
kanıtlandı, tahmin değil):

| VM byte | Aracın dediği | Gerçek | Kanıt |
|---|---|---|---|
| 0x09 | Ret | **Dup** | method_26 tam 51 komut = `ldc 11; newarr; 11×(dup,ldc,ldstr,stelem.ref); stloc; ldstr; ldloc; String::Join; ret` |
| 0x89 | Sizeof | **Newarr** | aynı desen; `ldc.i4 16; X System.Byte; stloc` sonucu `set_IV(byte[])`'e gidiyor |
| 0x50 | Shl | **Stelem_Ref** | dizi/indeks/değer üçlüsünü tüketen tek aday |
| 0x4B | Ret | **Ldlen** | 5 kullanımın 4'ü `ldarg/ldloc(dizi); X; 0x00` deseninde |
| 0x00 | Ldlen | **Conv_I4** | `Call get_Length()→System.Int64; X; Call method_460(System.Int32)` — iki bağımsız yerde |

Sonuç: `method_26()` = 11 parçalı base64, `method_27()` = "UNPACKED"; `method_23` artık
exception atmadan çalışıyor (`Form1` ilverify hatası 7→0, dosya geneli 71→64). Kurtarılan
mantık: `PBKDF2(parola, field_3, 8192)` → 32 bayt AES anahtarı, AES-CBC, IV = şifreli
metnin ilk 16 baytı, çözülen metin `== "UNPACKED"`.

**ASIL ARAÇ HATASI — `Ret` dejenere yerel optimum (düzeltildi).**
`SemanticValidation`'ın yeniden-ayar döngüleri bir adayı "geriye kalan CIL hata sayısı"
ile puanlıyor. Bu hedef fonksiyonunun bozuk bir optimumu var: bir byte'ı `Ret` (ya da
Throw/EndFinally) yaparsan metodun geri kalanı ERİŞİLEMEZ olur, recompiler onu atar ve
hata sayısı çöker — metot "doğrulanır" çünkü neredeyse hiçbir yeri kalmamıştır. Log kanıtı
(düzeltmeden önce): `vm 0x09/0x7E/0x4B/0x20/0x53 -> Ret` ve
`cil issues 61331 -> 0`. Yani araç programı silerek "sıfır hata" elde ediyordu.

FIX (`Krypton.Pipeline/Stages/SemanticValidation.Reachability.cs` + `SemanticValidation.cs`):
`CountReachableVmInstructions` (CFG + EH giriş noktalarıyla erişilebilirlik yürüyüşü,
override-farkındalı) ve `ScoreState = hataSayısı + (toplamKomut - erişilebilirKomut)`.
Bu MUTLAK ölçek her iki yönü de dürüst tutar: kırpma artık kazanamaz, ama önceki bir
kırpmanın sakladığı kodu geri getiren bir aday da getirdiği hatalarla bedelini ödeyebilir.
Obfuscator'ın gerçekten ölü bıraktığı kod her durumda erişilemez olduğu için sadece sabit
ekler. Üç döngüye de uygulandı (VM-güdümlü, CIL-güdümlü, entry-underflow).
Doğrulandı: bu hedefte `0x09 -> Ret` artık seçilmiyor; WFA37'de `0x07 -> Ret` yerine
`Conv_U8` seçiliyor, değiştirilen metot sayısı ve hata modu birebir aynı (regresyon yok).

**`TargetedJointSolver` kullanılabilir hale getirildi:** hedef metotları `"::ad("` ile
arıyordu, ama bu aşamada isimler henüz obfuske (kontrol karakterli) olduğu için HİÇBİR
hedef eşleşmiyordu ("no target method matched") — yani çözücü pratikte ölüydü. Artık
`key:<MethodKey>` ile ve genel alt-dizeyle (tip adı dahil) eşleşiyor. Örnek:
`KRYPTON_TYPE_CONSTRAINTS=1 KRYPTON_GLOBAL_STACK_SOLVER=1 KRYPTON_JOINT_TARGET_SOLVE=1
KRYPTON_JOINT_TARGET_METHODS="key:201,key:365,key:523,key:629" KRYPTON_APPLY_TYPE_ANCHORS=1`.
Bu hedefte çalışıyor ama 15 serbest değişkenle düğüm sınırına takılıp INCONCLUSIVE
kalıyor — yakınsaması için önce `TypeConstraintAnchoring`'in daha çok byte çapalaması
gerekiyor (AÇIK İŞ).

**AÇIK: bu 5 byte hâlâ elle override ile veriliyor.** Kalıcı çalışan komut:
```
KRYPTON_FORCE_VM_MAP="0x09=Dup;0x89=Newarr;0x50=Stelem_Ref;0x4B=Ldlen;0x00=Conv_I4"
```
Tek-byte tırmanma bunları kendi bulamıyor çünkü `method_26`'nın doğrulanması için 0x09,
0x50 ve 0x89'un AYNI ANDA doğru olması gerekiyor — klasik yerel optimum vadisi. Doğru
çözüm ortak (joint) arama; mekanizma var, çapalama zayıf.

**Uçtan uca doğrulama:** override'la `ilverify` 64 hata (Form1'de 0), `Devirtualized.exe`
çalışıyor, pencere açılıyor, butona basınca çökmüyor. Reflection probe:
`method_23("test123") = False`, `method_27() = "UNPACKED"`. Parola bulunmadı (PBKDF2
8192 tur; kullanıcı şimdilik istemedi).

## 2026-09-05 — Tip-farkındalı kısıt denetleyicisi (`TypedStackConstraint`) — DERLENDİ, ÖLÇÜLMEDİ

Amaç: `Form1::method_23` için hâlâ elle verilen 5 override'ı
(`0x09=Dup;0x89=Newarr;0x50=Stelem_Ref;0x4B=Ldlen;0x00=Conv_I4`) aracın kendi
kanıtlaması.

**Teşhis (ölçüldü, kesin).** Mevcut çözücülerin hepsi yalnızca **yığın derinliği**
kontrol ediyordu (`GlobalStackConstraintSolver.IsStackConsistent`). `Ldtoken` ile
`Newarr` derinlik açısından ayırt EDİLEMEZ: ikisi de tip token'ı taşır, biri pop
edip biri etmese de arama ağacında ikisi de ayakta kalır. Kanıt, override'sız
baseline koşusunun kendi logu:

```
method ?? (7 instr, 7 distinct bytes)     <- Form1::method_27, MethodKey 629
  feasible found   : 4892                 <- derinlik kurallarına uyan 4892 tam atama
  candidates in/out: 0x09 26->26, 0x89 11->11, 0x5C 90->90 ...   (hiçbir daraltma yok)
method ?? (51 instr, 9 distinct bytes)    <- Form1::method_26, MethodKey 523
  feasible found   : 200584
```
Ayrıca `method_25` (49 instr, 14 byte) a-priori arama uzayı taşması nedeniyle hiç
aranmıyor ("search space exceeds cap", `MaxSearchSpace = 5e11`).

Ayıran şey **tip**: `RuntimeHelpers::InitializeArray(System.Array, System.RuntimeFieldHandle)`
imzası ilk argümanın dizi olduğunu söyler; `Ldtoken` ise struct (handle) üretir →
o slotu `Ldtoken` dolduramaz. Bu bilgi, derinlikler kadar opcode tablosundan
BAĞIMSIZ (yalnızca metadata imzaları).

**Eklenen (derlendi, 0 hata):** `Krypton.Pipeline/Stages/TypedStackConstraint.cs`
— aday atama altında metodu soyut TİPLERLE yürüten bir yorumlayıcı
(`IsTypeConsistent`). CFG + EH giriş noktaları, birleşme noktalarında
genişletme (farklı tipler → Unknown). Sadece KESİN çelişkide `false` döner;
bilinmeyen her şey geçirgen (yanlış bir çürütme doğru cevabı eleyeceği için).
Kaynaklar: çağrı/newobj imzaları, alan tipleri, yerel/argüman tipleri, dizi
komutları, `Ldtoken`→değer-tipi. `System.IntPtr/UIntPtr` bilerek çürütülmüyor
(doğrulanabilir IL'de int32 oraya akabiliyor). Bağlandığı iki yer:
1. `TargetedJointSolver.AllConsistent`
2. `GlobalStackConstraintSolver.Search` (hem kısmi hem tam atama kontrolü)

Yan değişiklik: `TypeConstraintAnchoring.{Classify, ClassifyDescriptor, Lookup,
IsValueTypeDeclaring}` ve `GlobalStackConstraintSolver.{TryGetEffect, FlowKind}`
`private`→`internal` yapıldı (kod kopyalamamak için). Anchoring'in kendi lattice'i
DEĞİŞTİRİLMEDİ: yeni "değer tipi"/"sayısal" kavramları yalnızca yeni dosyanın
içinde yaşıyor, mevcut çapalama davranışı birebir aynı.

**EKSİKLER / YAPILMAYANLAR (dürüst liste):**
1. **Yeni kod HİÇ çalıştırılmadı.** Sadece `dotnet build` geçti. Tip kontrolünün
   0x09/0x89/0x50/0x4B/0x00'ı gerçekten daralttığı ÖLÇÜLMEDİ. Bir sonraki adım
   tam olarak bu koşu:
   ```
   cd "C:\Users\root\Desktop\.NET Reactor v7.5.9.1"
   $env:KRYPTON_TYPE_CONSTRAINTS=1; $env:KRYPTON_GLOBAL_STACK_SOLVER=1
   dotnet C:\RE\tools\krypton-devirtualizer\Krypton\bin\Release\net8.0\Krypton.dll "NET Reactor Unpack Me.exe" --no-pause
   ```
   Bakılacak yer: log'daki "Global stack-constraint solving" bloğunda
   `feasible found` sayıları (4892/200584 belirgin şekilde düşmeli) ve
   `VM 0xNN [ANCHORED]` satırları.
2. **Ortak (joint) çözücü bu hedefte pratikte kullanılamaz.** Tip kontrolüyle
   birlikte denendi: 6 metot, 15 serbest değişken, bazı byte'ların 90 adayı
   (`0x5C`, `0x4B`) → 11 dakikada bitmedi, iptal edildi. `MaxNodes = 40M`
   burada anlamsız. Metot-başına arama (küçükten büyüğe, `Surviving` kademeli
   daralıyor) doğru kaldıraç; joint yolu şimdilik ölü.
3. **`method_25` hâlâ aranamıyor olabilir.** A-priori arama uzayı hesabı
   (`space = Π |domain|`) tip kontrolünden ÖNCE yapılıyor, yani tip daraltması
   küçük metotlardan kaskatlanıp domainleri küçültmezse bu metot yine "search
   space exceeds cap" ile atlanır. `0x4B`(Ldlen) ve `0x00`(Conv_I4) SADECE bu
   metotta geçtiği için, kaskat yetmezse bu iki byte çözülmez.
4. **`0x00` için beklenen belirsizlik.** `Conv_I4` / `Conv_U4` / `Conv_Ovf_I4`
   kaba lattice'te ayırt edilemez; hepsi Int32 üretir. Çözücü "tek değer" şartı
   arıyor, dolayısıyla muhtemelen ANCHORED yerine UNRESOLVED verecek. Gerekirse
   "davranışsal olarak birbirinin yerine geçen aile → kanonik üye" kuralı gerekir
   (henüz yok, tasarlanmadı).
5. **Otomatik yol hâlâ env değişkenine bağlı.** `KRYPTON_TYPE_CONSTRAINTS` +
   `KRYPTON_GLOBAL_STACK_SOLVER` (+ uygulamak için `KRYPTON_APPLY_TYPE_ANCHORS`)
   kapalı varsayılan. Override'ların gerçekten kalkması için, kanıtlanan
   çapaların varsayılan boru hattında uygulanması gerekir — kaynak adı
   "override" içermeli, yoksa `SemanticValidation` geri çevirir
   (bkz. `runtime-truth-override` dersi).
6. **Regresyon kontrolü yapılmadı.** WFA37 (Reactor 6.5) hedefinde çıktının
   birebir aynı kaldığı DOĞRULANMADI. Tip kontrolü sadece env-gated yollarda
   çalıştığı için varsayılan koşuda etkisi olmamalı, ama ölçülmedi.

**Hedef klasördeki mevcut `NET Reactor Unpack Me-Devirtualized.exe` ÇALIŞMAZ** —
o, bilerek override'sız üretilmiş baseline (butona basınca `method_23`'te
`InvalidProgramException`). Çalışan sürüm için hâlâ:
```
KRYPTON_FORCE_VM_MAP="0x09=Dup;0x89=Newarr;0x50=Stelem_Ref;0x4B=Ldlen;0x00=Conv_I4"
```
Baseline ölçümü (override'sız, referans): ilverify toplam 83 hata — 63'ü
zararsız `ThisUninitReturn` (Reactor'ın kendi stub'lanmış .ctor'ları),
19'u Form1'de (`method_25` 3, `method_26` 13, `method_27` 2 + 1 ReturnEmpty),
1 `UnmanagedPointer`. Bu 19 hata, 5 override uygulandığında 0'a iniyor.

### 2026-09-05 (2) — ölçüm yapıldı: tip kontrolü daraltıyor, ama bir ARAÇ HATASI açığa çıktı

**Ölçüm 1 (tip kontrolü metot-başına aramaya bağlı, override'lı koşu).** Daraltma
gerçek: `method_26`'da aday sayıları `0x09` 26→**4**, `0x89` 11→**6**, arama uzayı
556920→112320, uygun atama 200584→**88920**; `method_27`'de 4892→3240.
AMA sonuç YANLIŞTI: `0x09`'dan **`Dup` elendi** (kalanlar `EndFinally, Ret,
Rethrow, Throw` — yine kırpma-çekicisi). Yani tip geçişi DOĞRU CEVABI çürütüyordu.

**Teşhis için kalıcı öz-kontrol eklendi** (`SemanticValidation.ReportTypeCheckerDisagreements`):
her metot için ŞU AN GÖNDERİLEN eşlemeyi tip denetleyicisinden geçirir; çürütülürse
metot + VM index + byte + sebep loglanır. Tip geçişi yalnızca aday ELEMEK için
kullanıldığından, gönderilen eşlemenin çürütülmesi ya gerçek bir eşleme hatası ya da
denetleyici hatasıdır — ikisi de görünür olmalı. İlk çalıştırmada tek satırda
kök nedeni verdi:
```
[type-check] refuted in MethodKey 629 at VM index 1 (vm 0x89):
             Newarr wants Int32 in argument slot 0 but the stack holds a value type
```

**ASIL ARAÇ HATASI (genel, bu hedefe özel değil) — `Ldtoken` operand-türü.**
`TypeConstraintAnchoring.IsOperandUsageCompatible`, `Ldtoken`'ı
`Newarr/Box/Unbox_Any/Ldobj/Isinst/Castclass/Constrained/Ldelema/Stobj` ile aynı
`case` grubuna koyup operandının **ITypeDefOrRef** olmasını şart koşuyordu. Oysa
`ldtoken` tip, **alan** veya metot token'ı alabilir — katalogda zaten öyle tanımlı
(`VMMetadataTokenKind.Any`, `VMOpCodeCatalog.cs:164`) ve fonksiyonun başındaki genel
kontrol bunu doğru uyguluyor; alttaki switch onu çelişkili biçimde daraltıyordu.
Sonuç: `ldtoken <field>; call RuntimeHelpers::InitializeArray` deseni — .NET'te HER
dizi/string sabiti başlatıcısının standart kalıbı — kullanan her byte'tan `Ldtoken`
siliniyor, byte'a tek aday olarak `Ldc_I4` kalıyordu. `method_27`'de bu, `0x22`'yi
`{Ldc_I4}`'e kilitledi → `InitializeArray`'in `RuntimeFieldHandle` argümanı hiçbir
atamada sağlanamaz oldu → TÜM doğru atamalar çürüdü → geriye yalnızca metodu 2.
komutta kesen terminal opcode'lar kaldı. Kırpma-çekicisi burada scoring'den değil,
**boş bırakılmış bir aday kümesinden** doğuyordu.
FIX: `case VMOpCode.Ldtoken:` o gruptan çıkarıldı (neden yorumla yazıldı).
DOĞRULANDI: `0x22` 1→2 aday (`Ldc_I4, Ldtoken`), `0x09` artık `Dup`'ı KORUYOR
(26→15), hiçbir metotta yanlış çürütme yok.

**İkinci düzeltme — `Ldtoken`/`Ldc_I4` alçaltma yalanı.** `MethodRecompiling.
BuildLdtokenInstruction` operandı hiçbir üyeye çözülmeyen bir `Ldtoken`'ı `Ldc_I4`
olarak yayıyor (bilinen, kasıtlı geri düşüş). Tip denetleyicisi ise eşlemeye bakıp
"değer tipi" varsayıyordu → öz-kontrol `0x4F`/`0x07` üzerinden gürültü üretiyordu.
`TypedStackConstraint` artık alçaltıcıyı birebir modelliyor: operand çözülmüyorsa
`Ldtoken` **Int32** üretir. (Derlendi; doğrulama koşusu bu notu yazarken sürüyor.)

**ÖLÇÜM 2 SONUCU (Ldtoken fix'i ile): yeni ÇAPA YOK.**
`resolution states: ANCHORED=1 UNRESOLVED=47 INCONCLUSIVE=3` — tek çapa hâlâ
`0x71→Ldloc`. Yani yanlış çürütme giderildi ama 5 byte hâlâ kanıtlanamıyor.

**NEDEN kanıtlanamıyor (teşhis, tahmin değil):** metot-başına arama bir adayı ancak
HİÇBİR uygun atamada görünmüyorsa eliyor. `0x50`(Stelem_Ref), `0x4B`(Ldlen),
`0x00`(Conv_I4) modülde YALNIZCA birer metotta geçiyor (sırasıyla method_26,
method_25 ×2), dolayısıyla metotlar-arası kesişim kaldıracı yok; aynı metotta ise
`0x5C`(90 aday), `0x9B`, `0x89` gibi byte'lar serbestken derinlik+tip kurallarına
uyan ama anlamsız on binlerce atama var (method_26: 88920). Kısıtlar sağlam, sinyal
zayıf.

**SIRADAKİ ADIM (önerilen, henüz yapılmadı): metot-dönüş-değeri oracle'ı.**
`RuntimeFieldTruth` deseninin aynısı, alan değerleri yerine dönüş değerleriyle:
korumalı orijinal exe'de `method_27()` = `"UNPACKED"`, `method_26()` = 11 parçalı
base64 GÖZLEMLENEBİLİR. Aday atamayı derleyip çalıştırıp çıktıyı gözlemlenene
karşı test etmek `0x09/0x89/0x22`'yi tek çözüme indirir — çünkü bu bir kanıt,
oy değil. Aynı mekanizma `0x50` için `method_26`'yı, `0x4B/0x00` için
`method_25`'i (girdi/çıktı çifti bilinen AES yolu) kapsar.

**Ek iki düzeltme (aynı oturum, doğrulandı):**
- `TypedStackConstraint` artık `MethodRecompiling`'in alçaltmasını birebir modelliyor:
  operandı hiçbir üyeye çözülmeyen `Ldtoken` **Int32** üretir (recompiler onu zaten
  `Ldc_I4` olarak yayıyor). Öz-kontrol gürültüsü 3→2 satıra indi ve kalan iki satır
  GERÇEK: `0x97` doğrulama-öncesi `Ldtoken` eşlenmiş (olması gereken `Ldstr`;
  anchoring de "3 kısıt bunu eliyor" diyor) ve `method_274`'te `0x07=Shl`'in komşusu
  aynı sınıf hatayı taşıyor.
- `BuildLdtokenInstruction` uyarı seli: modülde **542 farklı** çözülemeyen sabit
  `Ldtoken` sanılıyor ve her biri her recompile turunda loglanıyordu. Artık token
  başına bir kez, en fazla 8 örnek + tek bir "gerisi bastırıldı" satırı.
  Ölçüldü: uyarı 1084→**16**, toplam log 1673→**572** satır; üretilen exe birebir
  aynı kalitede (ilverify 64 hata, Form1'de 0).

**Bu oturumda DEĞİŞMEYEN:** 5 override hâlâ gerekli, yeni çapa yok, WFA37
regresyon koşusu yapılmadı.

### 2026-09-05 (3) — build-all.ps1 artık Krypton.Runner'ı da derliyor + çalışma-zamanı doğrulaması

`build-all.ps1`, `Krypton.Runner`'ı (Krypton'un alt süreç olarak başlattığı .NET
Framework gözlemci hostu) derlemiyordu; proje referansı olmadığı için hiçbir şey onu
build'e sokmuyor, `Krypton\bin\Release\net8.0`'a kopyalamıyordu. Eksik olduğunda
NecroBit dumper'ı ve runtime-alan opcode çözücüsü HATA VERMEDEN sessizce devre dışı
kalıyor — en pahalı arıza türü. Artık script Runner'ı restore+build edip
`Krypton.Runner.exe/.config/.pdb` + `dnlib/0Harmony/Newtonsoft.Json`'ı host çıktısına
kopyalıyor; bulunamazsa açık uyarı basıyor. Sıfırdan (`bin` klasörleri silinerek)
doğrulandı.

**Doğrulama artık ilverify ile sınırlı değil.** `ilverify` "Form1'de 0 hata" dese bile
program çalışırken `InvalidProgramException` atabiliyor, o yüzden üretilen exe artık
yansımayla gerçekten çağrılarak sınanıyor (Windows PowerShell 5.1, -STA):
```
method_27() = UNPACKED
method_26() = DRGeFGvStcxgMrGb1uZTI56tbMP2XHH+5LNEMyMz6oM=
method_23('test123') = False      <- exception yok
```
Bu, override'lı temiz derlemeyle üretilen exe için geçerli.

**Tekrarlanan karışıklık:** override'sız koşulan her Krypton çalıştırması, bu 5 byte'ı
yine yanlış eşleyen (`0x09→Nop`, `0x89→Ldtoken`, `0x50→Shl`, `0x4B→Conv_U8`,
`0x00→Ldlen`) ve butona basınca `method_23`'te çöken bir exe üretir. Raporun
`source:env-override` içerip içermediğine bakmak bunu bir bakışta ayırt ettiriyor.

### 2026-09-05 (4) — üç CLR geçerlilik kuralı: 0x89 artık ARAÇ TARAFINDAN kanıtlanıyor

Sürükle-bırakta çöken exe'nin nedeni araçta bir bozulma değil: override'sız her koşu
5 byte'ı yanlış eşliyor. Bunu kapatmak için çözücüye üç **sağlam** (CLR kuralı, skor
değil) kısıt eklendi:

1. **Metodun sonundan düşülemez.** ECMA-335: komut akışı metodun sonundan düşemez;
   son komut kontrol aktarmalı (ret/throw/br/leave/endfinally). Eskiden yalnızca
   "yığın 0 değilse hata" deniyordu, yani derinliği 0'a denk gelen sahte atamalar
   geçiyordu. (`GlobalStackConstraintSolver`, complete kontrolü.)
2. **`EndFinally`/`Rethrow`/`Leave` ait olduğu bölgenin dışında olamaz.**
   `IsHandlerContextValid`: endfinally ancak finally/fault handler'ında, rethrow
   ancak catch/filter handler'ında, leave ancak korumalı bölge veya catch-benzeri
   handler içinde geçerli. Metotta HİÇ EH yoksa üçü de hiçbir yerde geçerli değil —
   bir byte'ın "yürüyüşü erken bitirmek için" bu terminallere park etmesini engeller.
3. **`Mkrefany`/`Refanytype` değer tipi üretir** (`TypedReference` struct'tır), yani
   `Array` isteyen bir argümanı dolduramaz. (`TypedStackConstraint`.)
   Ayrıca `Ret` artık **dönüş tipini** de kontrol ediyor (derinlik zaten kontrol
   ediliyordu, tip hiç kontrol edilmiyordu).

**Ölçülen etki (`method_27`, MethodKey 629, kapsamlı arama):**
uygun atama 562 → **8**. Kanıtlananlar: `0x22=Ldtoken`, `0x4F=Ldc_I4`,
`0x9C=Newobj`, `0x9D=Call`. Modül genelinde: **`0x89 -> Newarr` [ANCHORED]** —
5 override'dan biri artık gerçekten kanıtlanıyor. `0x09` 26→3 (`Dup, Ldnull, Throw`),
`0x5C` 90→2 (`Ret, Throw`).

**Uçtan uca doğrulandı:** `KRYPTON_FORCE_VM_MAP`'ten `0x89` ÇIKARILIP
`KRYPTON_TYPE_CONSTRAINTS=1 KRYPTON_JOINT_TARGET_SOLVE=1
KRYPTON_JOINT_TARGET_METHODS=key:629 KRYPTON_APPLY_TYPE_ANCHORS=1` ile koşulduğunda
rapor `0x89 -> Newarr, conf:1,00, source:metadata-signature` diyor ve program
çalışıyor (`method_27()`="UNPACKED", `method_26()`=base64, `method_23('test123')`=False).

**AMA çapaları uygulamak varsayılan yapılmadı:** aynı koşuda `ilverify` 64 → **146**
(Form1'de 0 → 3). Yükselişin kaynağı `0x4F` çapası (Ldtoken→Ldc_I4 düzeltmesi):
anchoring 15 kısıt sitesiyle Ldc_I4 diyor ve muhtemelen haklı, ama operandı gerçek
bir metadata üyesine çözülen `0x4F` kullanımlarında çıktı değişip başka metotları
bozuyor. Çalışma zamanı iyi, doğrulama kötü — çelişki çözülmeden `KRYPTON_APPLY_TYPE_ANCHORS`
kapalı kalmalı. (İNCELENECEK.)

**NEDEN geri kalan 4 byte hâlâ çözülemiyor (ölçüldü, tahmin değil):**
Metot-başına arama bir adayı ancak HİÇBİR uygun atamada görünmüyorsa eliyor.
`method_26`'da `0x50`'nin 90 adayının hepsi ayakta kalıyor çünkü aynı metottaki
`0x9B` (8 aday: Stloc/Ldloc/Ldc_I4 ve dört `Br*_Un`) dallanma seçildiğinde CFG
birleşme noktaları oluşuyor; birleşmede tipler `Unknown`'a genişliyor ve tip geçişi
hiçbir şeyi çürütemez hale geliyor. Yani tek bir "vahşi" byte, aynı metottaki tüm
diğer byte'ları geniş tutuyor. `0x09` için `Dup` vs `Ldnull` ve `0x5C` için
`Ret` vs `Throw` ayrımı ise 6 metodun HİÇBİRİNDE statik olarak yapılamıyor:
null bir dizi `stelem`e verilmek üzere yığına konabilir (statik olarak geçerli,
runtime'da NullReferenceException) ve her zaman fırlatan bir metot da geçerli IL'dir.

**SIRADAKİ KALDIRAÇ (değişmedi): metot-dönüş-değeri oracle'ı.** Korumalı orijinalde
`method_27()`="UNPACKED" gözlemlenebiliyor; kalan 8 (artık ~2-4) aday atamayı
üretip çalıştırıp gözlemle karşılaştırmak `0x09` ve `0x5C`'yi kanıta çevirir.
`RuntimeFieldTruth` bunu alan değerleri için zaten yapıyor; mekanizma mevcut.
