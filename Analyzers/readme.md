# Концепт утилиты анализатора позволяющий очень хорошо исследовать трафик MHDDOS_proxy

Работая в одной компании мне пришлось анализировать такую утилиту как MHDDOS. </br>
И благодаря достаточно поверхностному взгляду на трафик генерируемый утилитой удалось понять что она перед отправкой множества запросов посылала DNS запрос. </br>
Идея атаки заключалась в том чтобы за счёт добавления dns имен в файл hosts файл на устройстве заставлять утилиту выдавать весь список DNS по которым она должна вести атаку. </br>

### Данная атака успешно работала до 95 версии утилиты!!! При условии что с 45 версии атака методом обратной разработки была признана не эффективной!
