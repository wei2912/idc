#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "nibble_aes.h"

typedef struct {
    uint64_t pt;
    uint64_t ct;
} pt_ct_t;

typedef short (*match_diff_t)(const uint64_t a, const uint64_t b);


#define MASK_14025 0xff00f00f00ff0ff0
#define MASK_23130 0xf0f00f0ff0f00f0f
#define MASK_27795 0xf00f00ff0ff0ff00
#define MASK_37740 0xff0ff00f00f00ff
#define MASK_42405 0xf0ff0f00f0ff0f0
#define MASK_51510 0xff0ff0ff00f00f
#define MASK_2029 0xfffff000000f00f0
#define MASK_2942 0xffff0f00f000000f
#define MASK_3511 0xffff00f00f00f000
#define MASK_3803 0xffff000f00f00f00
#define MASK_4990 0xfff0ff00f000000f
#define MASK_5101 0xfff0ff00000f00f0
#define MASK_5613 0xfff0f0f0000f00f0
#define MASK_5851 0xfff0f00f00f00f00
#define MASK_5869 0xfff0f00f000f00f0
#define MASK_5997 0xfff0f000f00f00f0
#define MASK_6061 0xfff0f0000f0f00f0
#define MASK_6093 0xfff0f00000ff00f0
#define MASK_6117 0xfff0f000000ff0f0
#define MASK_6121 0xfff0f000000f0ff0
#define MASK_6124 0xfff0f000000f00ff
#define MASK_6526 0xfff00ff0f000000f
#define MASK_6782 0xfff00f0ff000000f
#define MASK_6875 0xfff00f0f00f00f00
#define MASK_6974 0xfff00f00ff00000f
#define MASK_7006 0xfff00f00f0f0000f
#define MASK_7022 0xfff00f00f00f000f
#define MASK_7030 0xfff00f00f000f00f
#define MASK_7034 0xfff00f00f0000f0f
#define MASK_7036 0xfff00f00f00000ff
#define MASK_7387 0xfff000ff00f00f00
#define MASK_7771 0xfff0000ff0f00f00
#define MASK_7835 0xfff0000f0ff00f00
#define MASK_7883 0xfff0000f00ff0f00
#define MASK_7891 0xfff0000f00f0ff00
#define MASK_7897 0xfff0000f00f00ff0
#define MASK_7898 0xfff0000f00f00f0f
#define MASK_9197 0xff0fff00000f00f0
#define MASK_9655 0xff0ff0f00f00f000
#define MASK_9709 0xff0ff0f0000f00f0
#define MASK_9947 0xff0ff00f00f00f00
#define MASK_9965 0xff0ff00f000f00f0
#define MASK_10093 0xff0ff000f00f00f0
#define MASK_10157 0xff0ff0000f0f00f0
#define MASK_10189 0xff0ff00000ff00f0
#define MASK_10213 0xff0ff000000ff0f0
#define MASK_10217 0xff0ff000000f0ff0
#define MASK_10220 0xff0ff000000f00ff
#define MASK_10679 0xff0f0ff00f00f000
#define MASK_10971 0xff0f0f0f00f00f00
#define MASK_11447 0xff0f00ff0f00f000
#define MASK_11483 0xff0f00ff00f00f00
#define MASK_11575 0xff0f00f0ff00f000
#define MASK_11671 0xff0f00f00ff0f000
#define MASK_11687 0xff0f00f00f0ff000
#define MASK_11699 0xff0f00f00f00ff00
#define MASK_11701 0xff0f00f00f00f0f0
#define MASK_11702 0xff0f00f00f00f00f
#define MASK_11867 0xff0f000ff0f00f00
#define MASK_11931 0xff0f000f0ff00f00
#define MASK_11979 0xff0f000f00ff0f00
#define MASK_11987 0xff0f000f00f0ff00
#define MASK_11993 0xff0f000f00f00ff0
#define MASK_11994 0xff0f000f00f00f0f
#define MASK_12781 0xff00fff0000f00f0
#define MASK_13019 0xff00ff0f00f00f00
#define MASK_13037 0xff00ff0f000f00f0
#define MASK_13165 0xff00ff00f00f00f0
#define MASK_13229 0xff00ff000f0f00f0
#define MASK_13261 0xff00ff0000ff00f0
#define MASK_13285 0xff00ff00000ff0f0
#define MASK_13289 0xff00ff00000f0ff0
#define MASK_13292 0xff00ff00000f00ff
#define MASK_13531 0xff00f0ff00f00f00
#define MASK_13549 0xff00f0ff000f00f0
#define MASK_13677 0xff00f0f0f00f00f0
#define MASK_13741 0xff00f0f00f0f00f0
#define MASK_13773 0xff00f0f000ff00f0
#define MASK_13797 0xff00f0f0000ff0f0
#define MASK_13801 0xff00f0f0000f0ff0
#define MASK_13804 0xff00f0f0000f00ff
#define MASK_13915 0xff00f00ff0f00f00
#define MASK_13933 0xff00f00ff00f00f0
#define MASK_13979 0xff00f00f0ff00f00
#define MASK_13997 0xff00f00f0f0f00f0
#define MASK_14035 0xff00f00f00f0ff00
#define MASK_14042 0xff00f00f00f00f0f
#define MASK_14053 0xff00f00f000ff0f0
#define MASK_14060 0xff00f00f000f00ff
#define MASK_14125 0xff00f000ff0f00f0
#define MASK_14157 0xff00f000f0ff00f0
#define MASK_14181 0xff00f000f00ff0f0
#define MASK_14185 0xff00f000f00f0ff0
#define MASK_14188 0xff00f000f00f00ff
#define MASK_14221 0xff00f0000fff00f0
#define MASK_14245 0xff00f0000f0ff0f0
#define MASK_14249 0xff00f0000f0f0ff0
#define MASK_14252 0xff00f0000f0f00ff
#define MASK_14277 0xff00f00000fff0f0
#define MASK_14284 0xff00f00000ff00ff
#define MASK_14305 0xff00f000000ffff0
#define MASK_14308 0xff00f000000ff0ff
#define MASK_14312 0xff00f000000f0fff
#define MASK_14555 0xff000fff00f00f00
#define MASK_14939 0xff000f0ff0f00f00
#define MASK_15003 0xff000f0f0ff00f00
#define MASK_15051 0xff000f0f00ff0f00
#define MASK_15059 0xff000f0f00f0ff00
#define MASK_15065 0xff000f0f00f00ff0
#define MASK_15066 0xff000f0f00f00f0f
#define MASK_15451 0xff0000fff0f00f00
#define MASK_15515 0xff0000ff0ff00f00
#define MASK_15563 0xff0000ff00ff0f00
#define MASK_15571 0xff0000ff00f0ff00
#define MASK_15577 0xff0000ff00f00ff0
#define MASK_15578 0xff0000ff00f00f0f
#define MASK_15899 0xff00000ffff00f00
#define MASK_15947 0xff00000ff0ff0f00
#define MASK_15955 0xff00000ff0f0ff00
#define MASK_15961 0xff00000ff0f00ff0
#define MASK_15962 0xff00000ff0f00f0f
#define MASK_16011 0xff00000f0fff0f00
#define MASK_16019 0xff00000f0ff0ff00
#define MASK_16025 0xff00000f0ff00ff0
#define MASK_16026 0xff00000f0ff00f0f
#define MASK_16067 0xff00000f00ffff00
#define MASK_16074 0xff00000f00ff0f0f
#define MASK_16081 0xff00000f00f0fff0
#define MASK_16082 0xff00000f00f0ff0f
#define MASK_16088 0xff00000f00f00fff
#define MASK_17278 0xf0ffff00f000000f
#define MASK_17847 0xf0fff0f00f00f000
#define MASK_18139 0xf0fff00f00f00f00
#define MASK_18814 0xf0ff0ff0f000000f
#define MASK_18871 0xf0ff0ff00f00f000
#define MASK_19070 0xf0ff0f0ff000000f
#define MASK_19163 0xf0ff0f0f00f00f00
#define MASK_19262 0xf0ff0f00ff00000f
#define MASK_19294 0xf0ff0f00f0f0000f
#define MASK_19310 0xf0ff0f00f00f000f
#define MASK_19318 0xf0ff0f00f000f00f
#define MASK_19322 0xf0ff0f00f0000f0f
#define MASK_19324 0xf0ff0f00f00000ff
#define MASK_19639 0xf0ff00ff0f00f000
#define MASK_19675 0xf0ff00ff00f00f00
#define MASK_19767 0xf0ff00f0ff00f000
#define MASK_19863 0xf0ff00f00ff0f000
#define MASK_19879 0xf0ff00f00f0ff000
#define MASK_19891 0xf0ff00f00f00ff00
#define MASK_19893 0xf0ff00f00f00f0f0
#define MASK_19894 0xf0ff00f00f00f00f
#define MASK_20059 0xf0ff000ff0f00f00
#define MASK_20123 0xf0ff000f0ff00f00
#define MASK_20171 0xf0ff000f00ff0f00
#define MASK_20179 0xf0ff000f00f0ff00
#define MASK_20185 0xf0ff000f00f00ff0
#define MASK_20186 0xf0ff000f00f00f0f
#define MASK_20862 0xf0f0fff0f000000f
#define MASK_21118 0xf0f0ff0ff000000f
#define MASK_21211 0xf0f0ff0f00f00f00
#define MASK_21310 0xf0f0ff00ff00000f
#define MASK_21342 0xf0f0ff00f0f0000f
#define MASK_21358 0xf0f0ff00f00f000f
#define MASK_21366 0xf0f0ff00f000f00f
#define MASK_21370 0xf0f0ff00f0000f0f
#define MASK_21372 0xf0f0ff00f00000ff
#define MASK_21723 0xf0f0f0ff00f00f00
#define MASK_22107 0xf0f0f00ff0f00f00
#define MASK_22171 0xf0f0f00f0ff00f00
#define MASK_22219 0xf0f0f00f00ff0f00
#define MASK_22227 0xf0f0f00f00f0ff00
#define MASK_22233 0xf0f0f00f00f00ff0
#define MASK_22234 0xf0f0f00f00f00f0f
#define MASK_22654 0xf0f00ffff000000f
#define MASK_22747 0xf0f00fff00f00f00
#define MASK_22846 0xf0f00ff0ff00000f
#define MASK_22878 0xf0f00ff0f0f0000f
#define MASK_22894 0xf0f00ff0f00f000f
#define MASK_22902 0xf0f00ff0f000f00f
#define MASK_22906 0xf0f00ff0f0000f0f
#define MASK_22908 0xf0f00ff0f00000ff
#define MASK_23102 0xf0f00f0fff00000f
#define MASK_23150 0xf0f00f0ff00f000f
#define MASK_23158 0xf0f00f0ff000f00f
#define MASK_23164 0xf0f00f0ff00000ff
#define MASK_23195 0xf0f00f0f0ff00f00
#define MASK_23243 0xf0f00f0f00ff0f00
#define MASK_23251 0xf0f00f0f00f0ff00
#define MASK_23257 0xf0f00f0f00f00ff0
#define MASK_23326 0xf0f00f00fff0000f
#define MASK_23342 0xf0f00f00ff0f000f
#define MASK_23350 0xf0f00f00ff00f00f
#define MASK_23354 0xf0f00f00ff000f0f
#define MASK_23356 0xf0f00f00ff0000ff
#define MASK_23374 0xf0f00f00f0ff000f
#define MASK_23382 0xf0f00f00f0f0f00f
#define MASK_23388 0xf0f00f00f0f000ff
#define MASK_23398 0xf0f00f00f00ff00f
#define MASK_23402 0xf0f00f00f00f0f0f
#define MASK_23404 0xf0f00f00f00f00ff
#define MASK_23410 0xf0f00f00f000ff0f
#define MASK_23412 0xf0f00f00f000f0ff
#define MASK_23416 0xf0f00f00f0000fff
#define MASK_23643 0xf0f000fff0f00f00
#define MASK_23707 0xf0f000ff0ff00f00
#define MASK_23755 0xf0f000ff00ff0f00
#define MASK_23763 0xf0f000ff00f0ff00
#define MASK_23769 0xf0f000ff00f00ff0
#define MASK_23770 0xf0f000ff00f00f0f
#define MASK_24091 0xf0f0000ffff00f00
#define MASK_24139 0xf0f0000ff0ff0f00
#define MASK_24147 0xf0f0000ff0f0ff00
#define MASK_24153 0xf0f0000ff0f00ff0
#define MASK_24203 0xf0f0000f0fff0f00
#define MASK_24211 0xf0f0000f0ff0ff00
#define MASK_24217 0xf0f0000f0ff00ff0
#define MASK_24218 0xf0f0000f0ff00f0f
#define MASK_24259 0xf0f0000f00ffff00
#define MASK_24265 0xf0f0000f00ff0ff0
#define MASK_24266 0xf0f0000f00ff0f0f
#define MASK_24273 0xf0f0000f00f0fff0
#define MASK_24274 0xf0f0000f00f0ff0f
#define MASK_24280 0xf0f0000f00f00fff
#define MASK_25015 0xf00ffff00f00f000
#define MASK_25307 0xf00fff0f00f00f00
#define MASK_25783 0xf00ff0ff0f00f000
#define MASK_25819 0xf00ff0ff00f00f00
#define MASK_25911 0xf00ff0f0ff00f000
#define MASK_26007 0xf00ff0f00ff0f000
#define MASK_26023 0xf00ff0f00f0ff000
#define MASK_26035 0xf00ff0f00f00ff00
#define MASK_26037 0xf00ff0f00f00f0f0
#define MASK_26038 0xf00ff0f00f00f00f
#define MASK_26203 0xf00ff00ff0f00f00
#define MASK_26267 0xf00ff00f0ff00f00
#define MASK_26315 0xf00ff00f00ff0f00
#define MASK_26323 0xf00ff00f00f0ff00
#define MASK_26329 0xf00ff00f00f00ff0
#define MASK_26330 0xf00ff00f00f00f0f
#define MASK_26807 0xf00f0fff0f00f000
#define MASK_26843 0xf00f0fff00f00f00
#define MASK_26935 0xf00f0ff0ff00f000
#define MASK_27031 0xf00f0ff00ff0f000
#define MASK_27047 0xf00f0ff00f0ff000
#define MASK_27059 0xf00f0ff00f00ff00
#define MASK_27061 0xf00f0ff00f00f0f0
#define MASK_27062 0xf00f0ff00f00f00f
#define MASK_27227 0xf00f0f0ff0f00f00
#define MASK_27291 0xf00f0f0f0ff00f00
#define MASK_27339 0xf00f0f0f00ff0f00
#define MASK_27347 0xf00f0f0f00f0ff00
#define MASK_27353 0xf00f0f0f00f00ff0
#define MASK_27354 0xf00f0f0f00f00f0f
#define MASK_27703 0xf00f00ffff00f000
#define MASK_27739 0xf00f00fff0f00f00
#define MASK_27815 0xf00f00ff0f0ff000
#define MASK_27829 0xf00f00ff0f00f0f0
#define MASK_27830 0xf00f00ff0f00f00f
#define MASK_27851 0xf00f00ff00ff0f00
#define MASK_27865 0xf00f00ff00f00ff0
#define MASK_27866 0xf00f00ff00f00f0f
#define MASK_27927 0xf00f00f0fff0f000
#define MASK_27943 0xf00f00f0ff0ff000
#define MASK_27955 0xf00f00f0ff00ff00
#define MASK_27957 0xf00f00f0ff00f0f0
#define MASK_27958 0xf00f00f0ff00f00f
#define MASK_28039 0xf00f00f00ffff000
#define MASK_28053 0xf00f00f00ff0f0f0
#define MASK_28054 0xf00f00f00ff0f00f
#define MASK_28067 0xf00f00f00f0fff00
#define MASK_28069 0xf00f00f00f0ff0f0
#define MASK_28070 0xf00f00f00f0ff00f
#define MASK_28081 0xf00f00f00f00fff0
#define MASK_28082 0xf00f00f00f00ff0f
#define MASK_28084 0xf00f00f00f00f0ff
#define MASK_28187 0xf00f000ffff00f00
#define MASK_28235 0xf00f000ff0ff0f00
#define MASK_28243 0xf00f000ff0f0ff00
#define MASK_28249 0xf00f000ff0f00ff0
#define MASK_28250 0xf00f000ff0f00f0f
#define MASK_28299 0xf00f000f0fff0f00
#define MASK_28313 0xf00f000f0ff00ff0
#define MASK_28314 0xf00f000f0ff00f0f
#define MASK_28355 0xf00f000f00ffff00
#define MASK_28361 0xf00f000f00ff0ff0
#define MASK_28362 0xf00f000f00ff0f0f
#define MASK_28369 0xf00f000f00f0fff0
#define MASK_28370 0xf00f000f00f0ff0f
#define MASK_28376 0xf00f000f00f00fff
#define MASK_28891 0xf000ffff00f00f00
#define MASK_29275 0xf000ff0ff0f00f00
#define MASK_29339 0xf000ff0f0ff00f00
#define MASK_29387 0xf000ff0f00ff0f00
#define MASK_29395 0xf000ff0f00f0ff00
#define MASK_29401 0xf000ff0f00f00ff0
#define MASK_29402 0xf000ff0f00f00f0f
#define MASK_29787 0xf000f0fff0f00f00
#define MASK_29851 0xf000f0ff0ff00f00
#define MASK_29899 0xf000f0ff00ff0f00
#define MASK_29907 0xf000f0ff00f0ff00
#define MASK_29913 0xf000f0ff00f00ff0
#define MASK_29914 0xf000f0ff00f00f0f
#define MASK_30235 0xf000f00ffff00f00
#define MASK_30283 0xf000f00ff0ff0f00
#define MASK_30291 0xf000f00ff0f0ff00
#define MASK_30297 0xf000f00ff0f00ff0
#define MASK_30298 0xf000f00ff0f00f0f
#define MASK_30347 0xf000f00f0fff0f00
#define MASK_30355 0xf000f00f0ff0ff00
#define MASK_30361 0xf000f00f0ff00ff0
#define MASK_30362 0xf000f00f0ff00f0f
#define MASK_30403 0xf000f00f00ffff00
#define MASK_30410 0xf000f00f00ff0f0f
#define MASK_30417 0xf000f00f00f0fff0
#define MASK_30418 0xf000f00f00f0ff0f
#define MASK_30424 0xf000f00f00f00fff
#define MASK_30811 0xf0000ffff0f00f00
#define MASK_30875 0xf0000fff0ff00f00
#define MASK_30923 0xf0000fff00ff0f00
#define MASK_30931 0xf0000fff00f0ff00
#define MASK_30937 0xf0000fff00f00ff0
#define MASK_30938 0xf0000fff00f00f0f
#define MASK_31259 0xf0000f0ffff00f00
#define MASK_31307 0xf0000f0ff0ff0f00
#define MASK_31315 0xf0000f0ff0f0ff00
#define MASK_31321 0xf0000f0ff0f00ff0
#define MASK_31371 0xf0000f0f0fff0f00
#define MASK_31379 0xf0000f0f0ff0ff00
#define MASK_31385 0xf0000f0f0ff00ff0
#define MASK_31386 0xf0000f0f0ff00f0f
#define MASK_31427 0xf0000f0f00ffff00
#define MASK_31433 0xf0000f0f00ff0ff0
#define MASK_31434 0xf0000f0f00ff0f0f
#define MASK_31441 0xf0000f0f00f0fff0
#define MASK_31442 0xf0000f0f00f0ff0f
#define MASK_31448 0xf0000f0f00f00fff
#define MASK_31771 0xf00000fffff00f00
#define MASK_31819 0xf00000fff0ff0f00
#define MASK_31827 0xf00000fff0f0ff00
#define MASK_31833 0xf00000fff0f00ff0
#define MASK_31834 0xf00000fff0f00f0f
#define MASK_31883 0xf00000ff0fff0f00
#define MASK_31897 0xf00000ff0ff00ff0
#define MASK_31898 0xf00000ff0ff00f0f
#define MASK_31939 0xf00000ff00ffff00
#define MASK_31945 0xf00000ff00ff0ff0
#define MASK_31946 0xf00000ff00ff0f0f
#define MASK_31953 0xf00000ff00f0fff0
#define MASK_31954 0xf00000ff00f0ff0f
#define MASK_31960 0xf00000ff00f00fff
#define MASK_32267 0xf000000fffff0f00
#define MASK_32275 0xf000000ffff0ff00
#define MASK_32281 0xf000000ffff00ff0
#define MASK_32282 0xf000000ffff00f0f
#define MASK_32323 0xf000000ff0ffff00
#define MASK_32329 0xf000000ff0ff0ff0
#define MASK_32330 0xf000000ff0ff0f0f
#define MASK_32337 0xf000000ff0f0fff0
#define MASK_32338 0xf000000ff0f0ff0f
#define MASK_32344 0xf000000ff0f00fff
#define MASK_32387 0xf000000f0fffff00
#define MASK_32393 0xf000000f0fff0ff0
#define MASK_32394 0xf000000f0fff0f0f
#define MASK_32401 0xf000000f0ff0fff0
#define MASK_32402 0xf000000f0ff0ff0f
#define MASK_32408 0xf000000f0ff00fff
#define MASK_32449 0xf000000f00fffff0
#define MASK_32450 0xf000000f00ffff0f
#define MASK_32456 0xf000000f00ff0fff
#define MASK_32464 0xf000000f00f0ffff
#define MASK_33662 0xfffff00f000000f
#define MASK_33773 0xfffff00000f00f0
#define MASK_34231 0xffff0f00f00f000
#define MASK_34285 0xffff0f0000f00f0
#define MASK_34541 0xffff00f000f00f0
#define MASK_34669 0xffff000f00f00f0
#define MASK_34733 0xffff0000f0f00f0
#define MASK_34765 0xffff00000ff00f0
#define MASK_34789 0xffff000000ff0f0
#define MASK_34793 0xffff000000f0ff0
#define MASK_34796 0xffff000000f00ff
#define MASK_35198 0xfff0ff0f000000f
#define MASK_35255 0xfff0ff00f00f000
#define MASK_35454 0xfff0f0ff000000f
#define MASK_35646 0xfff0f00ff00000f
#define MASK_35678 0xfff0f00f0f0000f
#define MASK_35694 0xfff0f00f00f000f
#define MASK_35702 0xfff0f00f000f00f
#define MASK_35706 0xfff0f00f0000f0f
#define MASK_35708 0xfff0f00f00000ff
#define MASK_36023 0xfff00ff0f00f000
#define MASK_36151 0xfff00f0ff00f000
#define MASK_36247 0xfff00f00ff0f000
#define MASK_36263 0xfff00f00f0ff000
#define MASK_36275 0xfff00f00f00ff00
#define MASK_36277 0xfff00f00f00f0f0
#define MASK_36278 0xfff00f00f00f00f
#define MASK_37246 0xff0fff0f000000f
#define MASK_37357 0xff0fff0000f00f0
#define MASK_37502 0xff0ff0ff000000f
#define MASK_37613 0xff0ff0f000f00f0
#define MASK_37694 0xff0ff00ff00000f
#define MASK_37726 0xff0ff00f0f0000f
#define MASK_37750 0xff0ff00f000f00f
#define MASK_37754 0xff0ff00f0000f0f
#define MASK_37805 0xff0ff000f0f00f0
#define MASK_37837 0xff0ff0000ff00f0
#define MASK_37861 0xff0ff00000ff0f0
#define MASK_37865 0xff0ff00000f0ff0
#define MASK_38125 0xff0f0ff000f00f0
#define MASK_38253 0xff0f0f0f00f00f0
#define MASK_38317 0xff0f0f00f0f00f0
#define MASK_38349 0xff0f0f000ff00f0
#define MASK_38373 0xff0f0f0000ff0f0
#define MASK_38377 0xff0f0f0000f0ff0
#define MASK_38380 0xff0f0f0000f00ff
#define MASK_38509 0xff0f00ff00f00f0
#define MASK_38573 0xff0f00f0f0f00f0
#define MASK_38605 0xff0f00f00ff00f0
#define MASK_38629 0xff0f00f000ff0f0
#define MASK_38633 0xff0f00f000f0ff0
#define MASK_38636 0xff0f00f000f00ff
#define MASK_38701 0xff0f000ff0f00f0
#define MASK_38733 0xff0f000f0ff00f0
#define MASK_38757 0xff0f000f00ff0f0
#define MASK_38761 0xff0f000f00f0ff0
#define MASK_38797 0xff0f0000fff00f0
#define MASK_38821 0xff0f0000f0ff0f0
#define MASK_38825 0xff0f0000f0f0ff0
#define MASK_38828 0xff0f0000f0f00ff
#define MASK_38853 0xff0f00000fff0f0
#define MASK_38857 0xff0f00000ff0ff0
#define MASK_38860 0xff0f00000ff00ff
#define MASK_38881 0xff0f000000ffff0
#define MASK_38884 0xff0f000000ff0ff
#define MASK_38888 0xff0f000000f0fff
#define MASK_39038 0xff00ffff000000f
#define MASK_39230 0xff00ff0ff00000f
#define MASK_39262 0xff00ff0f0f0000f
#define MASK_39278 0xff00ff0f00f000f
#define MASK_39286 0xff00ff0f000f00f
#define MASK_39290 0xff00ff0f0000f0f
#define MASK_39292 0xff00ff0f00000ff
#define MASK_39486 0xff00f0fff00000f
#define MASK_39518 0xff00f0ff0f0000f
#define MASK_39534 0xff00f0ff00f000f
#define MASK_39542 0xff00f0ff000f00f
#define MASK_39546 0xff00f0ff0000f0f
#define MASK_39548 0xff00f0ff00000ff
#define MASK_39710 0xff00f00fff0000f
#define MASK_39726 0xff00f00ff0f000f
#define MASK_39734 0xff00f00ff00f00f
#define MASK_39738 0xff00f00ff000f0f
#define MASK_39740 0xff00f00ff0000ff
#define MASK_39758 0xff00f00f0ff000f
#define MASK_39766 0xff00f00f0f0f00f
#define MASK_39770 0xff00f00f0f00f0f
#define MASK_39772 0xff00f00f0f000ff
#define MASK_39782 0xff00f00f00ff00f
#define MASK_39786 0xff00f00f00f0f0f
#define MASK_39794 0xff00f00f000ff0f
#define MASK_39796 0xff00f00f000f0ff
#define MASK_39800 0xff00f00f0000fff
#define MASK_41399 0xf0ffff00f00f000
#define MASK_41453 0xf0ffff0000f00f0
#define MASK_41709 0xf0fff0f000f00f0
#define MASK_41837 0xf0fff00f00f00f0
#define MASK_41901 0xf0fff000f0f00f0
#define MASK_41933 0xf0fff0000ff00f0
#define MASK_41957 0xf0fff00000ff0f0
#define MASK_41961 0xf0fff00000f0ff0
#define MASK_41964 0xf0fff00000f00ff
#define MASK_42167 0xf0ff0ff0f00f000
#define MASK_42221 0xf0ff0ff000f00f0
#define MASK_42295 0xf0ff0f0ff00f000
#define MASK_42349 0xf0ff0f0f00f00f0
#define MASK_42391 0xf0ff0f00ff0f000
#define MASK_42419 0xf0ff0f00f00ff00
#define MASK_42422 0xf0ff0f00f00f00f
#define MASK_42445 0xf0ff0f000ff00f0
#define MASK_42473 0xf0ff0f0000f0ff0
#define MASK_42476 0xf0ff0f0000f00ff
#define MASK_42605 0xf0ff00ff00f00f0
#define MASK_42669 0xf0ff00f0f0f00f0
#define MASK_42701 0xf0ff00f00ff00f0
#define MASK_42725 0xf0ff00f000ff0f0
#define MASK_42729 0xf0ff00f000f0ff0
#define MASK_42732 0xf0ff00f000f00ff
#define MASK_42797 0xf0ff000ff0f00f0
#define MASK_42829 0xf0ff000f0ff00f0
#define MASK_42853 0xf0ff000f00ff0f0
#define MASK_42857 0xf0ff000f00f0ff0
#define MASK_42860 0xf0ff000f00f00ff
#define MASK_42893 0xf0ff0000fff00f0
#define MASK_42921 0xf0ff0000f0f0ff0
#define MASK_42924 0xf0ff0000f0f00ff
#define MASK_42949 0xf0ff00000fff0f0
#define MASK_42953 0xf0ff00000ff0ff0
#define MASK_42956 0xf0ff00000ff00ff
#define MASK_42977 0xf0ff000000ffff0
#define MASK_42980 0xf0ff000000ff0ff
#define MASK_42984 0xf0ff000000f0fff
#define MASK_43191 0xf0f0fff0f00f000
#define MASK_43319 0xf0f0ff0ff00f000
#define MASK_43415 0xf0f0ff00ff0f000
#define MASK_43431 0xf0f0ff00f0ff000
#define MASK_43443 0xf0f0ff00f00ff00
#define MASK_43445 0xf0f0ff00f00f0f0
#define MASK_43446 0xf0f0ff00f00f00f
#define MASK_44087 0xf0f00ffff00f000
#define MASK_44183 0xf0f00ff0ff0f000
#define MASK_44199 0xf0f00ff0f0ff000
#define MASK_44211 0xf0f00ff0f00ff00
#define MASK_44213 0xf0f00ff0f00f0f0
#define MASK_44214 0xf0f00ff0f00f00f
#define MASK_44311 0xf0f00f0fff0f000
#define MASK_44327 0xf0f00f0ff0ff000
#define MASK_44339 0xf0f00f0ff00ff00
#define MASK_44341 0xf0f00f0ff00f0f0
#define MASK_44342 0xf0f00f0ff00f00f
#define MASK_44423 0xf0f00f00ffff000
#define MASK_44435 0xf0f00f00ff0ff00
#define MASK_44437 0xf0f00f00ff0f0f0
#define MASK_44438 0xf0f00f00ff0f00f
#define MASK_44451 0xf0f00f00f0fff00
#define MASK_44454 0xf0f00f00f0ff00f
#define MASK_44465 0xf0f00f00f00fff0
#define MASK_44466 0xf0f00f00f00ff0f
#define MASK_44468 0xf0f00f00f00f0ff
#define MASK_45293 0xf00ffff000f00f0
#define MASK_45421 0xf00fff0f00f00f0
#define MASK_45485 0xf00fff00f0f00f0
#define MASK_45517 0xf00fff000ff00f0
#define MASK_45541 0xf00fff0000ff0f0
#define MASK_45545 0xf00fff0000f0ff0
#define MASK_45548 0xf00fff0000f00ff
#define MASK_45677 0xf00ff0ff00f00f0
#define MASK_45741 0xf00ff0f0f0f00f0
#define MASK_45773 0xf00ff0f00ff00f0
#define MASK_45797 0xf00ff0f000ff0f0
#define MASK_45801 0xf00ff0f000f0ff0
#define MASK_45804 0xf00ff0f000f00ff
#define MASK_45869 0xf00ff00ff0f00f0
#define MASK_45901 0xf00ff00f0ff00f0
#define MASK_45925 0xf00ff00f00ff0f0
#define MASK_45929 0xf00ff00f00f0ff0
#define MASK_45965 0xf00ff000fff00f0
#define MASK_45989 0xf00ff000f0ff0f0
#define MASK_45993 0xf00ff000f0f0ff0
#define MASK_45996 0xf00ff000f0f00ff
#define MASK_46021 0xf00ff0000fff0f0
#define MASK_46025 0xf00ff0000ff0ff0
#define MASK_46028 0xf00ff0000ff00ff
#define MASK_46049 0xf00ff00000ffff0
#define MASK_46052 0xf00ff00000ff0ff
#define MASK_46056 0xf00ff00000f0fff
#define MASK_46189 0xf00f0fff00f00f0
#define MASK_46253 0xf00f0ff0f0f00f0
#define MASK_46285 0xf00f0ff00ff00f0
#define MASK_46309 0xf00f0ff000ff0f0
#define MASK_46313 0xf00f0ff000f0ff0
#define MASK_46316 0xf00f0ff000f00ff
#define MASK_46381 0xf00f0f0ff0f00f0
#define MASK_46413 0xf00f0f0f0ff00f0
#define MASK_46437 0xf00f0f0f00ff0f0
#define MASK_46441 0xf00f0f0f00f0ff0
#define MASK_46444 0xf00f0f0f00f00ff
#define MASK_46477 0xf00f0f00fff00f0
#define MASK_46505 0xf00f0f00f0f0ff0
#define MASK_46508 0xf00f0f00f0f00ff
#define MASK_46533 0xf00f0f000fff0f0
#define MASK_46537 0xf00f0f000ff0ff0
#define MASK_46540 0xf00f0f000ff00ff
#define MASK_46561 0xf00f0f0000ffff0
#define MASK_46564 0xf00f0f0000ff0ff
#define MASK_46568 0xf00f0f0000f0fff
#define MASK_46637 0xf00f00fff0f00f0
#define MASK_46669 0xf00f00ff0ff00f0
#define MASK_46693 0xf00f00ff00ff0f0
#define MASK_46697 0xf00f00ff00f0ff0
#define MASK_46700 0xf00f00ff00f00ff
#define MASK_46733 0xf00f00f0fff00f0
#define MASK_46757 0xf00f00f0f0ff0f0
#define MASK_46761 0xf00f00f0f0f0ff0
#define MASK_46764 0xf00f00f0f0f00ff
#define MASK_46789 0xf00f00f00fff0f0
#define MASK_46796 0xf00f00f00ff00ff
#define MASK_46817 0xf00f00f000ffff0
#define MASK_46820 0xf00f00f000ff0ff
#define MASK_46824 0xf00f00f000f0fff
#define MASK_46861 0xf00f000ffff00f0
#define MASK_46885 0xf00f000ff0ff0f0
#define MASK_46889 0xf00f000ff0f0ff0
#define MASK_46892 0xf00f000ff0f00ff
#define MASK_46917 0xf00f000f0fff0f0
#define MASK_46921 0xf00f000f0ff0ff0
#define MASK_46924 0xf00f000f0ff00ff
#define MASK_46945 0xf00f000f00ffff0
#define MASK_46948 0xf00f000f00ff0ff
#define MASK_46952 0xf00f000f00f0fff
#define MASK_46981 0xf00f0000ffff0f0
#define MASK_46985 0xf00f0000fff0ff0
#define MASK_46988 0xf00f0000fff00ff
#define MASK_47009 0xf00f0000f0ffff0
#define MASK_47012 0xf00f0000f0ff0ff
#define MASK_47016 0xf00f0000f0f0fff
#define MASK_47041 0xf00f00000fffff0
#define MASK_47044 0xf00f00000fff0ff
#define MASK_47048 0xf00f00000ff0fff
#define MASK_47072 0xf00f000000fffff
#define MASK_49534 0xfffff0f000000f
#define MASK_49591 0xfffff00f00f000
#define MASK_49790 0xffff0ff000000f
#define MASK_49982 0xffff00ff00000f
#define MASK_50014 0xffff00f0f0000f
#define MASK_50030 0xffff00f00f000f
#define MASK_50038 0xffff00f000f00f
#define MASK_50042 0xffff00f0000f0f
#define MASK_50044 0xffff00f00000ff
#define MASK_50359 0xfff0ff0f00f000
#define MASK_50487 0xfff0f0ff00f000
#define MASK_50583 0xfff0f00ff0f000
#define MASK_50599 0xfff0f00f0ff000
#define MASK_50611 0xfff0f00f00ff00
#define MASK_50613 0xfff0f00f00f0f0
#define MASK_50614 0xfff0f00f00f00f
#define MASK_51326 0xff0ffff000000f
#define MASK_51383 0xff0fff0f00f000
#define MASK_51550 0xff0ff0f0f0000f
#define MASK_51566 0xff0ff0f00f000f
#define MASK_51578 0xff0ff0f0000f0f
#define MASK_51580 0xff0ff0f00000ff
#define MASK_51607 0xff0ff00ff0f000
#define MASK_51623 0xff0ff00f0ff000
#define MASK_51635 0xff0ff00f00ff00
#define MASK_51637 0xff0ff00f00f0f0
#define MASK_51774 0xff0f0fff00000f
#define MASK_51806 0xff0f0ff0f0000f
#define MASK_51822 0xff0f0ff00f000f
#define MASK_51830 0xff0f0ff000f00f
#define MASK_51834 0xff0f0ff0000f0f
#define MASK_51836 0xff0f0ff00000ff
#define MASK_51998 0xff0f00fff0000f
#define MASK_52014 0xff0f00ff0f000f
#define MASK_52026 0xff0f00ff000f0f
#define MASK_52028 0xff0f00ff0000ff
#define MASK_52046 0xff0f00f0ff000f
#define MASK_52054 0xff0f00f0f0f00f
#define MASK_52058 0xff0f00f0f00f0f
#define MASK_52060 0xff0f00f0f000ff
#define MASK_52070 0xff0f00f00ff00f
#define MASK_52074 0xff0f00f00f0f0f
#define MASK_52076 0xff0f00f00f00ff
#define MASK_52082 0xff0f00f000ff0f
#define MASK_52084 0xff0f00f000f0ff
#define MASK_52088 0xff0f00f0000fff
#define MASK_52279 0xff00ffff00f000
#define MASK_52375 0xff00ff0ff0f000
#define MASK_52391 0xff00ff0f0ff000
#define MASK_52403 0xff00ff0f00ff00
#define MASK_52405 0xff00ff0f00f0f0
#define MASK_52406 0xff00ff0f00f00f
#define MASK_52503 0xff00f0fff0f000
#define MASK_52519 0xff00f0ff0ff000
#define MASK_52531 0xff00f0ff00ff00
#define MASK_52533 0xff00f0ff00f0f0
#define MASK_52615 0xff00f00ffff000
#define MASK_52627 0xff00f00ff0ff00
#define MASK_52629 0xff00f00ff0f0f0
#define MASK_52630 0xff00f00ff0f00f
#define MASK_52643 0xff00f00f0fff00
#define MASK_52645 0xff00f00f0ff0f0
#define MASK_52646 0xff00f00f0ff00f
#define MASK_52657 0xff00f00f00fff0
#define MASK_52658 0xff00f00f00ff0f
#define MASK_52660 0xff00f00f00f0ff
#define MASK_53374 0xf0fffff000000f
#define MASK_53566 0xf0fff0ff00000f
#define MASK_53598 0xf0fff0f0f0000f
#define MASK_53614 0xf0fff0f00f000f
#define MASK_53622 0xf0fff0f000f00f
#define MASK_53626 0xf0fff0f0000f0f
#define MASK_53628 0xf0fff0f00000ff
#define MASK_53822 0xf0ff0fff00000f
#define MASK_53854 0xf0ff0ff0f0000f
#define MASK_53870 0xf0ff0ff00f000f
#define MASK_53878 0xf0ff0ff000f00f
#define MASK_53882 0xf0ff0ff0000f0f
#define MASK_53884 0xf0ff0ff00000ff
#define MASK_54046 0xf0ff00fff0000f
#define MASK_54062 0xf0ff00ff0f000f
#define MASK_54070 0xf0ff00ff00f00f
#define MASK_54074 0xf0ff00ff000f0f
#define MASK_54076 0xf0ff00ff0000ff
#define MASK_54094 0xf0ff00f0ff000f
#define MASK_54102 0xf0ff00f0f0f00f
#define MASK_54106 0xf0ff00f0f00f0f
#define MASK_54108 0xf0ff00f0f000ff
#define MASK_54118 0xf0ff00f00ff00f
#define MASK_54122 0xf0ff00f00f0f0f
#define MASK_54130 0xf0ff00f000ff0f
#define MASK_54132 0xf0ff00f000f0ff
#define MASK_54136 0xf0ff00f0000fff
#define MASK_55358 0xf00fffff00000f
#define MASK_55390 0xf00ffff0f0000f
#define MASK_55406 0xf00ffff00f000f
#define MASK_55414 0xf00ffff000f00f
#define MASK_55418 0xf00ffff0000f0f
#define MASK_55420 0xf00ffff00000ff
#define MASK_55582 0xf00ff0fff0000f
#define MASK_55598 0xf00ff0ff0f000f
#define MASK_55610 0xf00ff0ff000f0f
#define MASK_55612 0xf00ff0ff0000ff
#define MASK_55630 0xf00ff0f0ff000f
#define MASK_55638 0xf00ff0f0f0f00f
#define MASK_55642 0xf00ff0f0f00f0f
#define MASK_55644 0xf00ff0f0f000ff
#define MASK_55654 0xf00ff0f00ff00f
#define MASK_55658 0xf00ff0f00f0f0f
#define MASK_55660 0xf00ff0f00f00ff
#define MASK_55666 0xf00ff0f000ff0f
#define MASK_55668 0xf00ff0f000f0ff
#define MASK_55672 0xf00ff0f0000fff
#define MASK_55838 0xf00f0ffff0000f
#define MASK_55854 0xf00f0fff0f000f
#define MASK_55862 0xf00f0fff00f00f
#define MASK_55866 0xf00f0fff000f0f
#define MASK_55868 0xf00f0fff0000ff
#define MASK_55886 0xf00f0ff0ff000f
#define MASK_55894 0xf00f0ff0f0f00f
#define MASK_55900 0xf00f0ff0f000ff
#define MASK_55910 0xf00f0ff00ff00f
#define MASK_55914 0xf00f0ff00f0f0f
#define MASK_55916 0xf00f0ff00f00ff
#define MASK_55922 0xf00f0ff000ff0f
#define MASK_55924 0xf00f0ff000f0ff
#define MASK_55928 0xf00f0ff0000fff
#define MASK_56078 0xf00f00ffff000f
#define MASK_56086 0xf00f00fff0f00f
#define MASK_56090 0xf00f00fff00f0f
#define MASK_56092 0xf00f00fff000ff
#define MASK_56102 0xf00f00ff0ff00f
#define MASK_56106 0xf00f00ff0f0f0f
#define MASK_56108 0xf00f00ff0f00ff
#define MASK_56114 0xf00f00ff00ff0f
#define MASK_56116 0xf00f00ff00f0ff
#define MASK_56120 0xf00f00ff000fff
#define MASK_56134 0xf00f00f0fff00f
#define MASK_56138 0xf00f00f0ff0f0f
#define MASK_56140 0xf00f00f0ff00ff
#define MASK_56146 0xf00f00f0f0ff0f
#define MASK_56148 0xf00f00f0f0f0ff
#define MASK_56152 0xf00f00f0f00fff
#define MASK_56162 0xf00f00f00fff0f
#define MASK_56164 0xf00f00f00ff0ff
#define MASK_56168 0xf00f00f00f0fff
#define MASK_56176 0xf00f00f000ffff
#define MASK_57527 0xfffff0f00f000
#define MASK_57655 0xffff0ff00f000
#define MASK_57751 0xffff00ff0f000
#define MASK_57767 0xffff00f0ff000
#define MASK_57779 0xffff00f00ff00
#define MASK_57781 0xffff00f00f0f0
#define MASK_57782 0xffff00f00f00f
#define MASK_58423 0xff0ffff00f000
#define MASK_58519 0xff0ff0ff0f000
#define MASK_58535 0xff0ff0f0ff000
#define MASK_58547 0xff0ff0f00ff00
#define MASK_58549 0xff0ff0f00f0f0
#define MASK_58550 0xff0ff0f00f00f
#define MASK_58647 0xff0f0fff0f000
#define MASK_58663 0xff0f0ff0ff000
#define MASK_58675 0xff0f0ff00ff00
#define MASK_58677 0xff0f0ff00f0f0
#define MASK_58678 0xff0f0ff00f00f
#define MASK_58759 0xff0f00ffff000
#define MASK_58771 0xff0f00ff0ff00
#define MASK_58773 0xff0f00ff0f0f0
#define MASK_58774 0xff0f00ff0f00f
#define MASK_58787 0xff0f00f0fff00
#define MASK_58790 0xff0f00f0ff00f
#define MASK_58801 0xff0f00f00fff0
#define MASK_58802 0xff0f00f00ff0f
#define MASK_58804 0xff0f00f00f0ff
#define MASK_59447 0xf0fffff00f000
#define MASK_59543 0xf0fff0ff0f000
#define MASK_59559 0xf0fff0f0ff000
#define MASK_59571 0xf0fff0f00ff00
#define MASK_59573 0xf0fff0f00f0f0
#define MASK_59574 0xf0fff0f00f00f
#define MASK_59671 0xf0ff0fff0f000
#define MASK_59687 0xf0ff0ff0ff000
#define MASK_59699 0xf0ff0ff00ff00
#define MASK_59701 0xf0ff0ff00f0f0
#define MASK_59783 0xf0ff00ffff000
#define MASK_59795 0xf0ff00ff0ff00
#define MASK_59797 0xf0ff00ff0f0f0
#define MASK_59798 0xf0ff00ff0f00f
#define MASK_59811 0xf0ff00f0fff00
#define MASK_59813 0xf0ff00f0ff0f0
#define MASK_59814 0xf0ff00f0ff00f
#define MASK_59825 0xf0ff00f00fff0
#define MASK_59826 0xf0ff00f00ff0f
#define MASK_59828 0xf0ff00f00f0ff
#define MASK_60439 0xf00fffff0f000
#define MASK_60455 0xf00ffff0ff000
#define MASK_60467 0xf00ffff00ff00
#define MASK_60469 0xf00ffff00f0f0
#define MASK_60470 0xf00ffff00f00f
#define MASK_60551 0xf00ff0ffff000
#define MASK_60565 0xf00ff0ff0f0f0
#define MASK_60566 0xf00ff0ff0f00f
#define MASK_60579 0xf00ff0f0fff00
#define MASK_60581 0xf00ff0f0ff0f0
#define MASK_60582 0xf00ff0f0ff00f
#define MASK_60593 0xf00ff0f00fff0
#define MASK_60594 0xf00ff0f00ff0f
#define MASK_60596 0xf00ff0f00f0ff
#define MASK_60679 0xf00f0fffff000
#define MASK_60691 0xf00f0fff0ff00
#define MASK_60693 0xf00f0fff0f0f0
#define MASK_60694 0xf00f0fff0f00f
#define MASK_60707 0xf00f0ff0fff00
#define MASK_60709 0xf00f0ff0ff0f0
#define MASK_60710 0xf00f0ff0ff00f
#define MASK_60721 0xf00f0ff00fff0
#define MASK_60722 0xf00f0ff00ff0f
#define MASK_60724 0xf00f0ff00f0ff
#define MASK_60803 0xf00f00fffff00
#define MASK_60805 0xf00f00ffff0f0
#define MASK_60806 0xf00f00ffff00f
#define MASK_60817 0xf00f00ff0fff0
#define MASK_60818 0xf00f00ff0ff0f
#define MASK_60820 0xf00f00ff0f0ff
#define MASK_60833 0xf00f00f0ffff0
#define MASK_60834 0xf00f00f0fff0f
#define MASK_60836 0xf00f00f0ff0ff
#define MASK_60848 0xf00f00f00ffff

static short is_match_diff_6210(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_14025(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14025;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14025;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14025(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_23130(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23130;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23130;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23130(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27795(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27795;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27795;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27795(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_37740(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37740;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37740;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37740(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42405(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42405;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42405;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42405(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51510(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51510;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51510;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51510(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_2029(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_2029;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_2029;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_2029(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF)
    );
}

static int cmp_passive_2942(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_2942;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_2942;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_2942(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF)
    );
}

static int cmp_passive_3511(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_3511;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_3511;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_3511(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF)
    );
}

static int cmp_passive_3803(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_3803;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_3803;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_3803(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF)
    );
}

static int cmp_passive_4990(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_4990;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_4990;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_4990(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_5101(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_5101;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_5101;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_5101(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_5613(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_5613;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_5613;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_5613(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_5851(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_5851;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_5851;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_5851(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_5869(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_5869;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_5869;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_5869(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_5997(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_5997;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_5997;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_5997(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6061(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6061;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6061;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6061(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6093(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6093;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6093;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6093(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6117(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6117;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6117;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6117(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6121(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6121;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6121;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6121(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6124(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6124;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6124;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6124(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6526(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6526;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6526;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6526(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6782(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6782;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6782;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6782(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6875(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6875;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6875;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6875(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_6974(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_6974;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_6974;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_6974(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7006(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7006;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7006;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7006(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7022(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7022;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7022;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7022(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7030(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7030;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7030;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7030(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7034(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7034;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7034;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7034(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7036(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7036;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7036;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7036(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7387(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7387;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7387;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7387(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7771(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7771;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7771;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7771(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7835(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7835;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7835;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7835(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7883(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7883;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7883;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7883(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7891(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7891;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7891;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7891(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7897(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7897;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7897;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7897(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_7898(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_7898;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_7898;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_7898(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF)
    );
}

static int cmp_passive_9197(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_9197;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_9197;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_9197(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_9655(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_9655;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_9655;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_9655(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_9709(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_9709;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_9709;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_9709(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_9947(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_9947;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_9947;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_9947(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_9965(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_9965;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_9965;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_9965(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10093(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10093;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10093;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10093(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10157(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10157;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10157;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10157(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10189(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10189;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10189;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10189(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10213(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10213;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10213;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10213(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10217(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10217;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10217;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10217(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10220(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10220;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10220;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10220(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10679(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10679;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10679;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10679(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_10971(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_10971;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_10971;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_10971(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11447(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11447;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11447;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11447(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11483(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11483;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11483;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11483(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11575(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11575;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11575;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11575(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11671(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11671;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11671;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11671(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11687(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11687;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11687;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11687(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11699(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11699;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11699;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11699(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11701(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11701;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11701;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11701(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11702(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11702;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11702;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11702(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11867(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11867;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11867;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11867(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11931(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11931;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11931;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11931(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11979(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11979;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11979;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11979(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11987(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11987;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11987;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11987(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11993(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11993;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11993;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11993(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_11994(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_11994;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_11994;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_11994(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_12781(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_12781;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_12781;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_12781(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13019(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13019;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13019;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13019(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13037(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13037;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13037;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13037(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13165(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13165;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13165;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13165(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13229(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13229;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13229;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13229(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13261(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13261;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13261;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13261(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13285(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13285;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13285;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13285(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13289(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13289;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13289;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13289(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13292(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13292;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13292;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13292(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13531(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13531;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13531;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13531(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13549(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13549;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13549;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13549(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13677(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13677;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13677;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13677(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13741(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13741;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13741;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13741(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13773(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13773;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13773;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13773(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13797(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13797;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13797;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13797(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13801(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13801;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13801;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13801(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13804(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13804;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13804;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13804(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13915(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13915;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13915;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13915(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13933(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13933;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13933;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13933(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13979(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13979;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13979;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13979(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_13997(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_13997;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_13997;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_13997(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14035(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14035;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14035;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14035(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14042(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14042;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14042;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14042(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14053(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14053;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14053;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14053(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14060(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14060;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14060;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14060(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14125(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14125;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14125;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14125(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14157(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14157;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14157;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14157(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14181(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14181;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14181;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14181(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14185(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14185;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14185;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14185(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14188(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14188;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14188;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14188(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14221(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14221;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14221;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14221(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14245(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14245;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14245;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14245(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14249(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14249;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14249;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14249(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14252(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14252;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14252;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14252(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14277(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14277;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14277;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14277(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14284(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14284;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14284;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14284(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14305(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14305;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14305;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14305(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14308(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14308;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14308;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14308(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14312(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14312;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14312;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14312(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14555(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14555;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14555;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14555(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_14939(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_14939;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_14939;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_14939(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15003(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15003;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15003;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15003(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15051(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15051;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15051;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15051(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15059(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15059;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15059;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15059(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15065(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15065;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15065;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15065(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15066(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15066;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15066;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15066(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15451(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15451;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15451;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15451(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15515(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15515;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15515;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15515(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15563(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15563;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15563;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15563(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15571(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15571;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15571;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15571(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15577(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15577;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15577;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15577(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15578(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15578;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15578;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15578(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15899(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15899;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15899;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15899(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15947(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15947;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15947;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15947(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15955(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15955;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15955;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15955(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15961(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15961;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15961;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15961(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_15962(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_15962;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_15962;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_15962(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16011(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16011;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16011;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16011(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16019(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16019;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16019;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16019(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16025(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16025;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16025;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16025(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16026(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16026;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16026;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16026(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16067(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16067;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16067;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16067(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16074(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16074;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16074;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16074(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16081(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16081;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16081;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16081(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16082(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16082;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16082;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16082(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_16088(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_16088;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_16088;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_16088(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF)
    );
}

static int cmp_passive_17278(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_17278;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_17278;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_17278(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_17847(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_17847;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_17847;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_17847(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_18139(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_18139;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_18139;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_18139(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_18814(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_18814;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_18814;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_18814(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_18871(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_18871;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_18871;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_18871(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19070(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19070;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19070;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19070(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19163(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19163;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19163;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19163(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19262(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19262;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19262;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19262(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19294(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19294;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19294;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19294(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19310(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19310;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19310;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19310(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19318(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19318;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19318;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19318(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19322(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19322;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19322;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19322(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19324(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19324;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19324;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19324(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19639(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19639;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19639;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19639(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19675(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19675;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19675;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19675(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19767(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19767;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19767;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19767(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19863(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19863;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19863;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19863(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19879(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19879;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19879;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19879(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19891(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19891;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19891;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19891(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19893(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19893;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19893;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19893(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_19894(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_19894;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_19894;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_19894(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20059(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20059;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20059;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20059(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20123(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20123;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20123;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20123(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20171(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20171;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20171;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20171(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20179(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20179;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20179;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20179(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20185(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20185;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20185;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20185(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20186(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20186;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20186;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20186(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_20862(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_20862;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_20862;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_20862(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21118(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21118;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21118;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21118(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21211(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21211;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21211;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21211(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21310(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21310;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21310;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21310(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21342(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21342;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21342;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21342(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21358(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21358;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21358;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21358(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21366(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21366;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21366;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21366(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21370(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21370;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21370;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21370(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21372(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21372;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21372;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21372(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_21723(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_21723;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_21723;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_21723(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22107(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22107;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22107;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22107(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22171(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22171;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22171;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22171(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22219(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22219;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22219;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22219(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22227(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22227;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22227;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22227(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22233(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22233;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22233;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22233(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22234(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22234;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22234;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22234(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22654(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22654;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22654;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22654(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22747(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22747;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22747;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22747(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22846(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22846;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22846;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22846(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22878(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22878;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22878;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22878(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22894(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22894;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22894;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22894(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22902(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22902;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22902;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22902(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22906(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22906;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22906;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22906(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_22908(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_22908;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_22908;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_22908(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23102(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23102;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23102;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23102(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23150(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23150;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23150;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23150(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23158(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23158;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23158;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23158(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23164(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23164;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23164;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23164(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23195(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23195;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23195;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23195(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23243(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23243;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23243;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23243(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23251(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23251;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23251;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23251(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23257(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23257;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23257;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23257(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23326(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23326;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23326;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23326(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23342(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23342;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23342;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23342(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23350(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23350;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23350;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23350(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23354(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23354;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23354;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23354(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23356(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23356;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23356;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23356(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23374(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23374;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23374;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23374(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23382(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23382;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23382;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23382(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23388(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23388;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23388;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23388(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23398(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23398;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23398;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23398(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23402(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23402;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23402;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23402(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23404(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23404;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23404;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23404(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23410(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23410;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23410;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23410(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23412(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23412;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23412;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23412(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23416(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23416;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23416;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23416(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23643(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23643;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23643;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23643(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23707(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23707;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23707;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23707(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23755(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23755;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23755;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23755(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23763(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23763;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23763;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23763(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23769(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23769;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23769;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23769(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_23770(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_23770;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_23770;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_23770(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24091(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24091;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24091;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24091(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24139(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24139;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24139;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24139(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24147(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24147;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24147;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24147(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24153(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24153;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24153;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24153(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24203(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24203;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24203;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24203(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24211(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24211;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24211;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24211(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24217(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24217;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24217;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24217(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24218(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24218;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24218;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24218(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24259(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24259;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24259;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24259(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24265(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24265;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24265;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24265(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24266(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24266;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24266;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24266(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24273(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24273;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24273;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24273(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24274(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24274;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24274;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24274(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_24280(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_24280;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_24280;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_24280(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_25015(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_25015;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_25015;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_25015(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_25307(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_25307;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_25307;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_25307(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_25783(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_25783;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_25783;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_25783(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_25819(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_25819;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_25819;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_25819(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_25911(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_25911;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_25911;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_25911(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26007(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26007;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26007;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26007(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26023(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26023;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26023;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26023(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26035(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26035;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26035;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26035(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26037(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26037;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26037;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26037(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26038(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26038;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26038;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26038(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26203(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26203;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26203;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26203(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26267(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26267;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26267;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26267(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26315(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26315;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26315;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26315(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26323(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26323;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26323;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26323(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26329(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26329;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26329;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26329(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26330(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26330;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26330;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26330(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26807(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26807;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26807;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26807(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26843(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26843;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26843;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26843(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_26935(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_26935;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_26935;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_26935(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27031(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27031;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27031;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27031(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27047(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27047;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27047;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27047(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27059(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27059;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27059;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27059(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27061(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27061;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27061;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27061(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27062(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27062;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27062;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27062(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27227(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27227;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27227;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27227(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27291(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27291;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27291;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27291(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27339(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27339;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27339;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27339(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27347(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27347;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27347;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27347(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27353(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27353;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27353;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27353(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27354(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27354;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27354;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27354(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27703(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27703;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27703;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27703(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27739(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27739;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27739;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27739(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27815(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27815;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27815;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27815(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27829(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27829;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27829;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27829(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27830(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27830;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27830;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27830(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27851(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27851;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27851;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27851(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27865(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27865;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27865;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27865(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27866(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27866;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27866;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27866(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27927(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27927;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27927;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27927(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27943(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27943;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27943;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27943(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27955(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27955;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27955;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27955(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27957(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27957;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27957;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27957(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_27958(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_27958;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_27958;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_27958(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28039(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28039;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28039;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28039(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28053(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28053;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28053;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28053(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28054(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28054;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28054;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28054(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28067(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28067;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28067;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28067(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28069(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28069;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28069;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28069(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28070(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28070;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28070;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28070(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28081(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28081;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28081;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28081(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28082(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28082;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28082;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28082(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28084(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28084;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28084;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28084(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28187(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28187;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28187;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28187(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28235(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28235;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28235;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28235(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28243(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28243;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28243;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28243(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28249(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28249;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28249;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28249(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28250(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28250;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28250;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28250(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28299(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28299;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28299;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28299(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28313(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28313;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28313;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28313(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28314(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28314;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28314;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28314(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28355(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28355;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28355;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28355(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28361(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28361;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28361;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28361(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28362(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28362;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28362;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28362(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28369(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28369;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28369;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28369(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28370(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28370;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28370;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28370(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28376(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28376;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28376;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28376(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_28891(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_28891;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_28891;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_28891(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29275(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29275;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29275;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29275(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29339(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29339;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29339;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29339(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29387(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29387;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29387;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29387(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29395(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29395;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29395;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29395(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29401(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29401;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29401;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29401(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29402(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29402;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29402;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29402(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29787(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29787;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29787;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29787(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29851(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29851;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29851;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29851(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29899(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29899;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29899;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29899(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29907(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29907;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29907;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29907(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29913(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29913;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29913;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29913(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_29914(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_29914;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_29914;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_29914(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30235(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30235;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30235;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30235(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30283(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30283;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30283;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30283(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30291(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30291;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30291;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30291(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30297(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30297;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30297;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30297(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30298(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30298;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30298;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30298(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30347(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30347;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30347;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30347(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30355(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30355;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30355;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30355(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30361(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30361;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30361;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30361(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30362(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30362;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30362;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30362(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30403(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30403;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30403;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30403(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30410(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30410;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30410;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30410(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30417(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30417;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30417;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30417(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30418(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30418;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30418;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30418(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30424(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30424;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30424;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30424(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30811(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30811;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30811;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30811(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30875(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30875;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30875;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30875(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30923(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30923;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30923;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30923(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30931(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30931;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30931;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30931(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30937(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30937;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30937;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30937(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_30938(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_30938;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_30938;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_30938(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31259(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31259;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31259;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31259(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31307(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31307;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31307;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31307(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31315(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31315;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31315;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31315(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31321(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31321;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31321;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31321(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31371(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31371;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31371;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31371(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31379(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31379;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31379;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31379(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31385(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31385;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31385;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31385(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31386(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31386;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31386;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31386(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31427(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31427;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31427;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31427(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31433(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31433;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31433;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31433(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31434(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31434;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31434;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31434(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31441(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31441;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31441;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31441(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31442(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31442;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31442;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31442(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31448(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31448;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31448;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31448(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31771(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31771;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31771;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31771(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31819(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31819;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31819;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31819(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31827(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31827;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31827;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31827(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31833(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31833;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31833;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31833(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31834(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31834;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31834;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31834(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31883(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31883;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31883;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31883(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31897(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31897;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31897;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31897(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31898(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31898;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31898;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31898(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31939(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31939;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31939;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31939(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31945(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31945;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31945;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31945(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31946(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31946;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31946;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31946(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31953(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31953;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31953;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31953(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31954(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31954;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31954;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31954(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_31960(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_31960;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_31960;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_31960(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32267(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32267;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32267;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32267(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32275(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32275;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32275;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32275(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32281(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32281;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32281;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32281(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32282(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32282;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32282;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32282(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32323(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32323;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32323;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32323(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32329(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32329;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32329;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32329(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32330(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32330;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32330;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32330(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32337(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32337;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32337;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32337(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32338(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32338;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32338;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32338(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32344(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32344;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32344;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32344(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32387(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32387;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32387;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32387(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32393(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32393;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32393;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32393(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32394(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32394;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32394;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32394(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32401(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32401;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32401;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32401(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32402(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32402;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32402;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32402(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32408(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32408;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32408;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32408(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32449(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32449;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32449;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32449(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32450(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32450;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32450;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32450(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32456(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32456;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32456;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32456(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_32464(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_32464;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_32464;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_32464(const uint64_t a, const uint64_t b) {
    return (
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF)
    );
}

static int cmp_passive_33662(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_33662;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_33662;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_33662(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_33773(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_33773;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_33773;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_33773(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34231(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34231;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34231;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34231(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34285(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34285;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34285;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34285(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34541(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34541;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34541;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34541(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34669(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34669;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34669;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34669(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34733(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34733;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34733;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34733(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34765(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34765;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34765;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34765(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34789(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34789;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34789;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34789(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34793(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34793;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34793;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34793(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_34796(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_34796;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_34796;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_34796(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35198(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35198;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35198;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35198(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35255(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35255;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35255;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35255(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35454(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35454;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35454;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35454(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35646(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35646;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35646;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35646(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35678(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35678;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35678;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35678(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35694(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35694;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35694;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35694(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35702(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35702;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35702;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35702(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35706(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35706;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35706;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35706(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_35708(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_35708;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_35708;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_35708(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36023(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36023;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36023;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36023(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36151(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36151;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36151;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36151(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36247(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36247;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36247;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36247(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36263(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36263;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36263;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36263(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36275(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36275;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36275;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36275(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36277(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36277;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36277;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36277(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_36278(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_36278;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_36278;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_36278(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37246(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37246;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37246;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37246(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37357(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37357;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37357;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37357(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37502(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37502;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37502;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37502(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37613(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37613;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37613;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37613(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37694(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37694;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37694;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37694(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37726(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37726;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37726;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37726(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37750(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37750;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37750;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37750(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37754(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37754;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37754;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37754(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37805(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37805;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37805;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37805(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37837(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37837;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37837;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37837(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37861(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37861;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37861;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37861(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_37865(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_37865;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_37865;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_37865(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38125(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38125;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38125;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38125(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38253(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38253;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38253;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38253(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38317(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38317;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38317;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38317(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38349(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38349;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38349;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38349(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38373(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38373;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38373;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38373(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38377(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38377;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38377;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38377(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38380(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38380;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38380;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38380(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38509(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38509;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38509;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38509(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38573(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38573;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38573;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38573(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38605(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38605;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38605;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38605(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38629(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38629;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38629;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38629(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38633(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38633;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38633;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38633(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38636(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38636;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38636;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38636(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38701(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38701;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38701;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38701(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38733(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38733;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38733;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38733(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38757(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38757;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38757;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38757(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38761(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38761;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38761;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38761(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38797(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38797;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38797;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38797(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38821(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38821;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38821;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38821(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38825(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38825;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38825;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38825(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38828(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38828;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38828;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38828(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38853(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38853;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38853;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38853(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38857(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38857;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38857;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38857(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38860(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38860;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38860;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38860(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38881(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38881;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38881;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38881(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38884(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38884;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38884;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38884(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_38888(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_38888;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_38888;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_38888(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39038(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39038;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39038;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39038(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39230(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39230;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39230;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39230(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39262(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39262;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39262;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39262(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39278(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39278;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39278;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39278(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39286(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39286;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39286;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39286(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39290(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39290;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39290;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39290(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39292(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39292;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39292;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39292(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39486(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39486;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39486;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39486(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39518(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39518;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39518;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39518(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39534(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39534;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39534;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39534(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39542(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39542;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39542;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39542(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39546(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39546;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39546;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39546(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39548(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39548;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39548;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39548(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39710(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39710;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39710;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39710(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39726(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39726;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39726;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39726(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39734(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39734;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39734;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39734(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39738(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39738;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39738;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39738(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39740(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39740;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39740;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39740(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39758(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39758;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39758;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39758(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39766(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39766;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39766;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39766(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39770(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39770;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39770;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39770(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39772(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39772;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39772;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39772(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39782(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39782;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39782;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39782(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39786(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39786;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39786;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39786(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39794(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39794;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39794;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39794(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39796(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39796;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39796;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39796(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_39800(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_39800;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_39800;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_39800(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41399(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41399;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41399;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41399(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41453(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41453;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41453;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41453(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41709(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41709;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41709;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41709(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41837(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41837;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41837;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41837(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41901(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41901;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41901;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41901(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41933(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41933;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41933;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41933(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41957(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41957;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41957;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41957(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41961(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41961;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41961;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41961(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_41964(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_41964;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_41964;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_41964(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42167(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42167;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42167;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42167(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42221(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42221;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42221;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42221(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42295(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42295;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42295;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42295(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42349(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42349;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42349;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42349(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42391(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42391;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42391;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42391(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42419(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42419;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42419;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42419(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42422(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42422;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42422;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42422(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42445(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42445;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42445;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42445(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42473(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42473;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42473;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42473(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42476(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42476;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42476;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42476(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42605(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42605;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42605;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42605(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42669(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42669;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42669;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42669(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42701(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42701;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42701;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42701(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42725(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42725;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42725;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42725(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42729(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42729;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42729;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42729(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42732(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42732;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42732;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42732(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42797(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42797;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42797;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42797(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42829(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42829;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42829;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42829(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42853(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42853;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42853;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42853(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42857(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42857;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42857;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42857(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42860(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42860;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42860;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42860(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42893(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42893;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42893;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42893(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42921(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42921;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42921;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42921(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42924(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42924;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42924;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42924(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42949(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42949;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42949;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42949(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42953(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42953;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42953;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42953(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42956(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42956;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42956;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42956(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42977(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42977;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42977;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42977(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42980(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42980;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42980;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42980(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_42984(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_42984;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_42984;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_42984(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43191(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43191;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43191;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43191(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43319(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43319;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43319;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43319(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43415(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43415;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43415;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43415(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43431(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43431;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43431;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43431(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43443(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43443;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43443;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43443(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43445(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43445;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43445;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43445(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_43446(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_43446;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_43446;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_43446(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44087(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44087;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44087;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44087(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44183(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44183;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44183;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44183(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44199(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44199;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44199;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44199(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44211(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44211;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44211;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44211(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44213(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44213;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44213;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44213(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44214(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44214;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44214;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44214(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44311(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44311;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44311;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44311(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44327(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44327;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44327;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44327(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44339(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44339;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44339;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44339(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44341(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44341;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44341;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44341(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44342(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44342;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44342;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44342(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44423(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44423;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44423;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44423(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44435(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44435;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44435;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44435(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44437(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44437;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44437;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44437(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44438(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44438;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44438;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44438(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44451(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44451;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44451;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44451(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44454(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44454;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44454;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44454(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44465(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44465;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44465;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44465(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44466(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44466;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44466;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44466(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_44468(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_44468;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_44468;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_44468(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45293(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45293;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45293;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45293(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45421(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45421;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45421;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45421(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45485(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45485;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45485;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45485(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45517(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45517;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45517;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45517(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45541(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45541;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45541;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45541(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45545(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45545;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45545;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45545(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45548(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45548;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45548;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45548(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45677(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45677;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45677;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45677(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45741(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45741;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45741;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45741(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45773(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45773;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45773;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45773(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45797(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45797;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45797;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45797(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45801(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45801;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45801;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45801(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45804(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45804;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45804;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45804(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45869(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45869;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45869;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45869(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45901(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45901;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45901;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45901(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45925(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45925;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45925;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45925(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45929(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45929;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45929;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45929(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45965(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45965;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45965;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45965(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45989(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45989;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45989;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45989(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45993(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45993;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45993;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45993(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_45996(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_45996;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_45996;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_45996(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46021(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46021;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46021;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46021(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46025(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46025;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46025;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46025(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46028(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46028;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46028;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46028(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46049(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46049;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46049;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46049(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46052(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46052;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46052;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46052(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46056(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46056;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46056;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46056(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46189(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46189;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46189;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46189(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46253(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46253;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46253;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46253(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46285(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46285;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46285;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46285(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46309(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46309;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46309;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46309(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46313(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46313;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46313;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46313(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46316(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46316;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46316;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46316(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46381(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46381;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46381;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46381(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46413(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46413;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46413;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46413(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46437(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46437;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46437;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46437(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46441(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46441;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46441;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46441(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46444(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46444;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46444;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46444(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46477(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46477;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46477;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46477(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46505(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46505;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46505;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46505(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46508(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46508;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46508;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46508(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46533(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46533;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46533;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46533(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46537(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46537;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46537;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46537(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46540(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46540;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46540;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46540(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46561(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46561;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46561;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46561(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46564(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46564;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46564;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46564(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46568(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46568;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46568;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46568(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46637(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46637;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46637;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46637(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46669(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46669;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46669;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46669(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46693(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46693;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46693;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46693(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46697(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46697;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46697;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46697(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46700(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46700;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46700;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46700(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46733(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46733;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46733;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46733(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46757(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46757;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46757;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46757(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46761(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46761;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46761;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46761(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46764(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46764;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46764;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46764(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46789(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46789;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46789;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46789(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46796(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46796;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46796;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46796(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46817(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46817;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46817;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46817(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46820(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46820;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46820;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46820(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46824(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46824;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46824;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46824(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46861(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46861;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46861;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46861(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46885(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46885;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46885;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46885(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46889(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46889;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46889;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46889(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46892(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46892;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46892;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46892(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46917(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46917;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46917;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46917(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46921(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46921;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46921;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46921(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46924(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46924;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46924;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46924(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46945(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46945;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46945;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46945(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46948(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46948;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46948;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46948(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46952(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46952;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46952;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46952(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46981(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46981;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46981;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46981(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46985(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46985;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46985;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46985(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_46988(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_46988;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_46988;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_46988(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47009(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47009;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47009;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47009(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47012(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47012;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47012;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47012(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47016(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47016;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47016;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47016(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47041(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47041;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47041;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47041(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47044(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47044;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47044;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47044(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47048(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47048;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47048;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47048(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_47072(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_47072;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_47072;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_47072(const uint64_t a, const uint64_t b) {
    return (
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_49534(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_49534;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_49534;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_49534(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_49591(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_49591;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_49591;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_49591(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_49790(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_49790;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_49790;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_49790(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_49982(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_49982;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_49982;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_49982(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50014(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50014;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50014;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50014(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50030(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50030;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50030;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50030(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50038(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50038;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50038;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50038(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50042(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50042;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50042;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50042(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50044(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50044;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50044;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50044(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50359(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50359;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50359;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50359(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50487(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50487;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50487;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50487(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50583(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50583;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50583;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50583(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50599(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50599;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50599;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50599(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50611(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50611;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50611;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50611(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50613(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50613;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50613;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50613(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_50614(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_50614;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_50614;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_50614(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51326(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51326;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51326;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51326(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51383(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51383;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51383;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51383(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51550(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51550;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51550;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51550(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51566(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51566;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51566;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51566(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51578(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51578;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51578;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51578(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51580(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51580;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51580;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51580(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51607(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51607;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51607;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51607(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51623(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51623;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51623;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51623(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51635(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51635;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51635;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51635(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51637(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51637;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51637;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51637(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51774(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51774;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51774;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51774(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51806(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51806;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51806;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51806(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51822(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51822;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51822;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51822(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51830(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51830;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51830;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51830(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51834(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51834;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51834;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51834(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51836(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51836;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51836;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51836(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_51998(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_51998;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_51998;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_51998(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52014(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52014;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52014;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52014(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52026(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52026;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52026;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52026(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52028(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52028;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52028;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52028(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52046(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52046;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52046;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52046(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52054(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52054;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52054;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52054(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52058(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52058;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52058;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52058(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52060(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52060;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52060;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52060(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52070(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52070;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52070;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52070(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52074(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52074;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52074;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52074(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52076(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52076;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52076;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52076(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52082(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52082;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52082;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52082(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52084(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52084;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52084;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52084(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52088(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52088;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52088;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52088(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52279(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52279;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52279;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52279(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52375(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52375;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52375;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52375(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52391(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52391;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52391;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52391(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52403(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52403;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52403;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52403(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52405(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52405;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52405;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52405(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52406(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52406;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52406;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52406(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52503(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52503;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52503;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52503(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52519(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52519;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52519;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52519(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52531(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52531;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52531;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52531(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52533(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52533;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52533;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52533(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52615(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52615;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52615;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52615(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52627(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52627;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52627;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52627(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52629(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52629;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52629;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52629(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52630(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52630;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52630;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52630(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52643(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52643;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52643;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52643(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52645(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52645;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52645;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52645(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52646(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52646;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52646;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52646(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52657(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52657;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52657;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52657(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52658(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52658;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52658;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52658(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_52660(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_52660;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_52660;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_52660(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53374(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53374;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53374;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53374(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53566(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53566;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53566;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53566(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53598(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53598;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53598;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53598(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53614(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53614;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53614;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53614(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53622(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53622;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53622;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53622(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53626(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53626;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53626;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53626(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53628(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53628;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53628;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53628(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53822(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53822;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53822;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53822(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53854(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53854;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53854;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53854(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53870(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53870;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53870;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53870(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53878(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53878;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53878;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53878(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53882(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53882;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53882;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53882(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_53884(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_53884;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_53884;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_53884(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54046(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54046;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54046;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54046(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54062(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54062;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54062;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54062(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54070(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54070;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54070;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54070(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54074(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54074;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54074;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54074(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54076(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54076;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54076;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54076(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54094(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54094;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54094;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54094(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54102(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54102;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54102;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54102(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54106(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54106;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54106;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54106(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54108(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54108;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54108;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54108(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54118(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54118;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54118;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54118(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54122(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54122;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54122;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54122(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54130(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54130;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54130;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54130(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54132(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54132;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54132;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54132(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_54136(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_54136;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_54136;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_54136(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55358(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55358;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55358;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55358(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55390(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55390;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55390;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55390(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55406(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55406;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55406;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55406(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55414(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55414;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55414;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55414(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55418(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55418;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55418;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55418(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55420(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55420;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55420;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55420(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55582(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55582;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55582;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55582(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55598(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55598;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55598;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55598(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55610(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55610;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55610;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55610(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55612(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55612;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55612;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55612(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55630(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55630;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55630;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55630(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55638(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55638;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55638;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55638(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55642(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55642;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55642;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55642(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55644(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55644;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55644;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55644(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55654(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55654;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55654;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55654(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55658(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55658;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55658;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55658(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55660(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55660;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55660;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55660(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55666(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55666;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55666;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55666(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55668(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55668;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55668;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55668(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55672(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55672;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55672;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55672(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55838(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55838;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55838;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55838(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55854(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55854;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55854;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55854(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55862(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55862;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55862;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55862(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55866(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55866;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55866;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55866(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55868(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55868;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55868;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55868(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55886(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55886;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55886;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55886(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55894(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55894;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55894;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55894(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55900(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55900;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55900;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55900(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55910(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55910;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55910;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55910(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55914(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55914;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55914;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55914(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55916(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55916;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55916;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55916(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55922(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55922;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55922;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55922(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55924(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55924;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55924;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55924(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_55928(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_55928;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_55928;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_55928(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56078(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56078;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56078;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56078(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56086(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56086;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56086;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56086(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56090(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56090;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56090;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56090(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56092(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56092;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56092;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56092(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56102(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56102;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56102;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56102(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56106(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56106;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56106;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56106(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56108(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56108;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56108;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56108(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56114(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56114;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56114;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56114(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56116(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56116;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56116;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56116(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56120(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56120;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56120;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56120(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56134(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56134;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56134;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56134(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56138(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56138;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56138;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56138(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56140(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56140;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56140;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56140(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56146(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56146;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56146;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56146(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56148(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56148;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56148;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56148(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56152(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56152;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56152;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56152(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56162(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56162;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56162;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56162(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56164(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56164;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56164;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56164(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56168(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56168;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56168;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56168(const uint64_t a, const uint64_t b) {
    return (
        (a >> 12 & 0xF) != (b >> 12 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_56176(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_56176;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_56176;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_56176(const uint64_t a, const uint64_t b) {
    return (
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 24 & 0xF) != (b >> 24 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 36 & 0xF) != (b >> 36 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 48 & 0xF) != (b >> 48 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57527(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57527;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57527;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57527(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57655(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57655;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57655;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57655(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57751(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57751;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57751;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57751(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57767(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57767;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57767;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57767(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57779(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57779;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57779;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57779(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57781(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57781;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57781;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57781(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_57782(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_57782;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_57782;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_57782(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58423(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58423;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58423;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58423(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58519(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58519;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58519;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58519(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58535(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58535;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58535;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58535(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58547(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58547;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58547;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58547(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58549(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58549;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58549;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58549(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58550(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58550;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58550;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58550(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58647(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58647;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58647;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58647(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58663(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58663;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58663;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58663(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58675(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58675;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58675;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58675(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58677(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58677;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58677;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58677(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58678(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58678;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58678;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58678(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58759(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58759;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58759;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58759(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58771(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58771;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58771;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58771(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58773(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58773;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58773;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58773(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58774(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58774;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58774;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58774(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58787(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58787;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58787;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58787(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58790(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58790;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58790;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58790(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58801(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58801;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58801;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58801(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58802(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58802;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58802;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58802(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_58804(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_58804;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_58804;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_58804(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59447(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59447;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59447;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59447(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59543(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59543;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59543;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59543(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59559(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59559;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59559;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59559(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59571(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59571;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59571;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59571(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59573(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59573;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59573;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59573(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59574(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59574;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59574;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59574(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59671(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59671;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59671;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59671(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59687(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59687;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59687;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59687(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59699(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59699;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59699;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59699(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59701(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59701;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59701;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59701(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59783(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59783;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59783;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59783(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59795(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59795;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59795;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59795(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59797(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59797;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59797;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59797(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59798(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59798;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59798;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59798(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59811(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59811;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59811;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59811(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59813(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59813;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59813;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59813(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59814(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59814;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59814;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59814(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59825(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59825;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59825;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59825(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59826(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59826;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59826;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59826(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_59828(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_59828;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_59828;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_59828(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60439(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60439;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60439;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60439(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60455(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60455;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60455;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60455(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60467(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60467;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60467;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60467(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60469(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60469;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60469;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60469(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60470(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60470;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60470;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60470(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60551(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60551;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60551;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60551(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60565(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60565;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60565;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60565(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60566(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60566;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60566;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60566(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60579(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60579;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60579;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60579(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60581(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60581;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60581;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60581(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60582(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60582;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60582;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60582(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60593(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60593;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60593;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60593(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60594(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60594;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60594;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60594(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60596(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60596;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60596;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60596(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60679(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60679;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60679;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60679(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60691(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60691;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60691;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60691(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60693(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60693;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60693;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60693(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60694(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60694;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60694;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60694(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60707(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60707;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60707;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60707(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60709(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60709;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60709;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60709(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60710(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60710;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60710;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60710(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60721(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60721;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60721;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60721(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60722(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60722;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60722;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60722(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60724(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60724;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60724;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60724(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60803(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60803;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60803;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60803(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60805(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60805;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60805;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60805(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60806(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60806;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60806;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60806(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60817(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60817;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60817;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60817(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60818(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60818;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60818;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60818(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60820(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60820;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60820;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60820(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60833(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60833;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60833;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60833(const uint64_t a, const uint64_t b) {
    return (
        (a >> 0 & 0xF) != (b >> 0 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60834(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60834;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60834;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60834(const uint64_t a, const uint64_t b) {
    return (
        (a >> 4 & 0xF) != (b >> 4 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60836(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60836;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60836;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60836(const uint64_t a, const uint64_t b) {
    return (
        (a >> 8 & 0xF) != (b >> 8 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}

static int cmp_passive_60848(const void *a, const void *b) {
    uint64_t inta = ((pt_ct_t*) a)->ct & MASK_60848;
    uint64_t intb = ((pt_ct_t*) b)->ct & MASK_60848;
    return (inta < intb) ? -1 : (inta > intb);
}

static short is_match_diff_60848(const uint64_t a, const uint64_t b) {
    return (
        (a >> 16 & 0xF) != (b >> 16 & 0xF) &&
        (a >> 20 & 0xF) != (b >> 20 & 0xF) &&
        (a >> 28 & 0xF) != (b >> 28 & 0xF) &&
        (a >> 32 & 0xF) != (b >> 32 & 0xF) &&
        (a >> 40 & 0xF) != (b >> 40 & 0xF) &&
        (a >> 44 & 0xF) != (b >> 44 & 0xF) &&
        (a >> 52 & 0xF) != (b >> 52 & 0xF) &&
        (a >> 56 & 0xF) != (b >> 56 & 0xF) &&
        (a >> 60 & 0xF) != (b >> 60 & 0xF)
    );
}


static void gen_pt_cts(pt_ct_t *ptcts, const uint16_t *key, const uint64_t i) {
    uint16_t pt[4], ct[4];
    pt[0] = (i >> 36 & 0xFFF) << 4;
    pt[1] = i >> 24 & 0xFFF;
    pt[2] = ((i >> 20 & 0xF) << 12) | (i >> 12 & 0xFF);
    pt[3] = ((i >> 4 & 0xFF) << 8) | (i >> 0 & 0xF);

    uint16_t i0, i1, i2, i3;
    for (i0 = 0; i0 < 16; ++i0) {
    for (i1 = 0; i1 < 16; ++i1) {
    for (i2 = 0; i2 < 16; ++i2) {
    for (i3 = 0; i3 < 16; ++i3) {
    pt[0] &= 0xfff0;
    pt[0] |= i0;
    pt[1] &= 0xfff;
    pt[1] |= i1 << 12;
    pt[2] &= 0xf0ff;
    pt[2] |= i2 << 8;
    pt[3] &= 0xff0f;
    pt[3] |= i3 << 4;
    encrypt(pt, ct, key);

    pt_ct_t pt_ct = {};
    pt_ct.pt = convert_int(pt);
    pt_ct.ct = convert_int(ct);
    ptcts[i0 << 12 | i1 << 8 | i2 << 4 | i3 << 0] = pt_ct;
    }
    }
    }
    }
}

static void print_pairs(pt_ct_t *ptcts, uint16_t end, uint64_t mask, match_diff_t f) {
    uint32_t k, l;
    uint64_t inactive_nibs;
    for (k = 0; k < 65536; ++k) {
        inactive_nibs = ptcts[k].ct & mask;
        l = k + 1;
        while ((ptcts[l].ct & mask) == inactive_nibs) {
            if (
                is_match_diff_6210(ptcts[k].pt, ptcts[l].pt) &&
                f(ptcts[k].ct, ptcts[l].ct)
            ) {
                printf(
                    "%05d %016" PRIx64 " %016" PRIx64 " %016" PRIx64  " %016" PRIx64 "\n",
                    end,
                    ptcts[k].pt,
                    ptcts[k].ct,
                    ptcts[l].pt,
                    ptcts[l].ct
                );
            }
            ++l;
        }
    }
}

int main(int argc, char **argv) {
    if (argc != 4) {
        printf("Usage: %s [key] [start] [end]\n", argv[0]);
        return 1;
    }

    uint16_t key[4] = {};
    convert_array(strtoull(argv[1], NULL, 10), key);
    uint64_t start = strtoull(argv[2], NULL, 10);
    uint64_t end = strtoull(argv[3], NULL, 10);

    uint64_t i;
    pt_ct_t ptcts[65536] = {};
    for (i = start; i < end; ++i) {
        gen_pt_cts(ptcts, key, i);
        
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14025);
        print_pairs(ptcts, 14025, MASK_14025, is_match_diff_14025);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23130);
        print_pairs(ptcts, 23130, MASK_23130, is_match_diff_23130);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27795);
        print_pairs(ptcts, 27795, MASK_27795, is_match_diff_27795);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37740);
        print_pairs(ptcts, 37740, MASK_37740, is_match_diff_37740);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42405);
        print_pairs(ptcts, 42405, MASK_42405, is_match_diff_42405);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51510);
        print_pairs(ptcts, 51510, MASK_51510, is_match_diff_51510);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_2029);
        print_pairs(ptcts, 2029, MASK_2029, is_match_diff_2029);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_2942);
        print_pairs(ptcts, 2942, MASK_2942, is_match_diff_2942);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_3511);
        print_pairs(ptcts, 3511, MASK_3511, is_match_diff_3511);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_3803);
        print_pairs(ptcts, 3803, MASK_3803, is_match_diff_3803);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_4990);
        print_pairs(ptcts, 4990, MASK_4990, is_match_diff_4990);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_5101);
        print_pairs(ptcts, 5101, MASK_5101, is_match_diff_5101);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_5613);
        print_pairs(ptcts, 5613, MASK_5613, is_match_diff_5613);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_5851);
        print_pairs(ptcts, 5851, MASK_5851, is_match_diff_5851);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_5869);
        print_pairs(ptcts, 5869, MASK_5869, is_match_diff_5869);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_5997);
        print_pairs(ptcts, 5997, MASK_5997, is_match_diff_5997);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6061);
        print_pairs(ptcts, 6061, MASK_6061, is_match_diff_6061);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6093);
        print_pairs(ptcts, 6093, MASK_6093, is_match_diff_6093);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6117);
        print_pairs(ptcts, 6117, MASK_6117, is_match_diff_6117);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6121);
        print_pairs(ptcts, 6121, MASK_6121, is_match_diff_6121);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6124);
        print_pairs(ptcts, 6124, MASK_6124, is_match_diff_6124);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6526);
        print_pairs(ptcts, 6526, MASK_6526, is_match_diff_6526);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6782);
        print_pairs(ptcts, 6782, MASK_6782, is_match_diff_6782);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6875);
        print_pairs(ptcts, 6875, MASK_6875, is_match_diff_6875);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_6974);
        print_pairs(ptcts, 6974, MASK_6974, is_match_diff_6974);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7006);
        print_pairs(ptcts, 7006, MASK_7006, is_match_diff_7006);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7022);
        print_pairs(ptcts, 7022, MASK_7022, is_match_diff_7022);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7030);
        print_pairs(ptcts, 7030, MASK_7030, is_match_diff_7030);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7034);
        print_pairs(ptcts, 7034, MASK_7034, is_match_diff_7034);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7036);
        print_pairs(ptcts, 7036, MASK_7036, is_match_diff_7036);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7387);
        print_pairs(ptcts, 7387, MASK_7387, is_match_diff_7387);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7771);
        print_pairs(ptcts, 7771, MASK_7771, is_match_diff_7771);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7835);
        print_pairs(ptcts, 7835, MASK_7835, is_match_diff_7835);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7883);
        print_pairs(ptcts, 7883, MASK_7883, is_match_diff_7883);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7891);
        print_pairs(ptcts, 7891, MASK_7891, is_match_diff_7891);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7897);
        print_pairs(ptcts, 7897, MASK_7897, is_match_diff_7897);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_7898);
        print_pairs(ptcts, 7898, MASK_7898, is_match_diff_7898);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_9197);
        print_pairs(ptcts, 9197, MASK_9197, is_match_diff_9197);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_9655);
        print_pairs(ptcts, 9655, MASK_9655, is_match_diff_9655);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_9709);
        print_pairs(ptcts, 9709, MASK_9709, is_match_diff_9709);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_9947);
        print_pairs(ptcts, 9947, MASK_9947, is_match_diff_9947);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_9965);
        print_pairs(ptcts, 9965, MASK_9965, is_match_diff_9965);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10093);
        print_pairs(ptcts, 10093, MASK_10093, is_match_diff_10093);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10157);
        print_pairs(ptcts, 10157, MASK_10157, is_match_diff_10157);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10189);
        print_pairs(ptcts, 10189, MASK_10189, is_match_diff_10189);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10213);
        print_pairs(ptcts, 10213, MASK_10213, is_match_diff_10213);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10217);
        print_pairs(ptcts, 10217, MASK_10217, is_match_diff_10217);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10220);
        print_pairs(ptcts, 10220, MASK_10220, is_match_diff_10220);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10679);
        print_pairs(ptcts, 10679, MASK_10679, is_match_diff_10679);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_10971);
        print_pairs(ptcts, 10971, MASK_10971, is_match_diff_10971);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11447);
        print_pairs(ptcts, 11447, MASK_11447, is_match_diff_11447);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11483);
        print_pairs(ptcts, 11483, MASK_11483, is_match_diff_11483);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11575);
        print_pairs(ptcts, 11575, MASK_11575, is_match_diff_11575);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11671);
        print_pairs(ptcts, 11671, MASK_11671, is_match_diff_11671);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11687);
        print_pairs(ptcts, 11687, MASK_11687, is_match_diff_11687);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11699);
        print_pairs(ptcts, 11699, MASK_11699, is_match_diff_11699);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11701);
        print_pairs(ptcts, 11701, MASK_11701, is_match_diff_11701);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11702);
        print_pairs(ptcts, 11702, MASK_11702, is_match_diff_11702);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11867);
        print_pairs(ptcts, 11867, MASK_11867, is_match_diff_11867);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11931);
        print_pairs(ptcts, 11931, MASK_11931, is_match_diff_11931);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11979);
        print_pairs(ptcts, 11979, MASK_11979, is_match_diff_11979);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11987);
        print_pairs(ptcts, 11987, MASK_11987, is_match_diff_11987);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11993);
        print_pairs(ptcts, 11993, MASK_11993, is_match_diff_11993);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_11994);
        print_pairs(ptcts, 11994, MASK_11994, is_match_diff_11994);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_12781);
        print_pairs(ptcts, 12781, MASK_12781, is_match_diff_12781);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13019);
        print_pairs(ptcts, 13019, MASK_13019, is_match_diff_13019);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13037);
        print_pairs(ptcts, 13037, MASK_13037, is_match_diff_13037);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13165);
        print_pairs(ptcts, 13165, MASK_13165, is_match_diff_13165);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13229);
        print_pairs(ptcts, 13229, MASK_13229, is_match_diff_13229);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13261);
        print_pairs(ptcts, 13261, MASK_13261, is_match_diff_13261);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13285);
        print_pairs(ptcts, 13285, MASK_13285, is_match_diff_13285);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13289);
        print_pairs(ptcts, 13289, MASK_13289, is_match_diff_13289);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13292);
        print_pairs(ptcts, 13292, MASK_13292, is_match_diff_13292);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13531);
        print_pairs(ptcts, 13531, MASK_13531, is_match_diff_13531);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13549);
        print_pairs(ptcts, 13549, MASK_13549, is_match_diff_13549);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13677);
        print_pairs(ptcts, 13677, MASK_13677, is_match_diff_13677);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13741);
        print_pairs(ptcts, 13741, MASK_13741, is_match_diff_13741);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13773);
        print_pairs(ptcts, 13773, MASK_13773, is_match_diff_13773);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13797);
        print_pairs(ptcts, 13797, MASK_13797, is_match_diff_13797);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13801);
        print_pairs(ptcts, 13801, MASK_13801, is_match_diff_13801);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13804);
        print_pairs(ptcts, 13804, MASK_13804, is_match_diff_13804);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13915);
        print_pairs(ptcts, 13915, MASK_13915, is_match_diff_13915);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13933);
        print_pairs(ptcts, 13933, MASK_13933, is_match_diff_13933);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13979);
        print_pairs(ptcts, 13979, MASK_13979, is_match_diff_13979);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_13997);
        print_pairs(ptcts, 13997, MASK_13997, is_match_diff_13997);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14035);
        print_pairs(ptcts, 14035, MASK_14035, is_match_diff_14035);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14042);
        print_pairs(ptcts, 14042, MASK_14042, is_match_diff_14042);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14053);
        print_pairs(ptcts, 14053, MASK_14053, is_match_diff_14053);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14060);
        print_pairs(ptcts, 14060, MASK_14060, is_match_diff_14060);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14125);
        print_pairs(ptcts, 14125, MASK_14125, is_match_diff_14125);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14157);
        print_pairs(ptcts, 14157, MASK_14157, is_match_diff_14157);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14181);
        print_pairs(ptcts, 14181, MASK_14181, is_match_diff_14181);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14185);
        print_pairs(ptcts, 14185, MASK_14185, is_match_diff_14185);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14188);
        print_pairs(ptcts, 14188, MASK_14188, is_match_diff_14188);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14221);
        print_pairs(ptcts, 14221, MASK_14221, is_match_diff_14221);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14245);
        print_pairs(ptcts, 14245, MASK_14245, is_match_diff_14245);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14249);
        print_pairs(ptcts, 14249, MASK_14249, is_match_diff_14249);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14252);
        print_pairs(ptcts, 14252, MASK_14252, is_match_diff_14252);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14277);
        print_pairs(ptcts, 14277, MASK_14277, is_match_diff_14277);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14284);
        print_pairs(ptcts, 14284, MASK_14284, is_match_diff_14284);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14305);
        print_pairs(ptcts, 14305, MASK_14305, is_match_diff_14305);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14308);
        print_pairs(ptcts, 14308, MASK_14308, is_match_diff_14308);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14312);
        print_pairs(ptcts, 14312, MASK_14312, is_match_diff_14312);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14555);
        print_pairs(ptcts, 14555, MASK_14555, is_match_diff_14555);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_14939);
        print_pairs(ptcts, 14939, MASK_14939, is_match_diff_14939);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15003);
        print_pairs(ptcts, 15003, MASK_15003, is_match_diff_15003);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15051);
        print_pairs(ptcts, 15051, MASK_15051, is_match_diff_15051);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15059);
        print_pairs(ptcts, 15059, MASK_15059, is_match_diff_15059);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15065);
        print_pairs(ptcts, 15065, MASK_15065, is_match_diff_15065);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15066);
        print_pairs(ptcts, 15066, MASK_15066, is_match_diff_15066);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15451);
        print_pairs(ptcts, 15451, MASK_15451, is_match_diff_15451);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15515);
        print_pairs(ptcts, 15515, MASK_15515, is_match_diff_15515);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15563);
        print_pairs(ptcts, 15563, MASK_15563, is_match_diff_15563);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15571);
        print_pairs(ptcts, 15571, MASK_15571, is_match_diff_15571);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15577);
        print_pairs(ptcts, 15577, MASK_15577, is_match_diff_15577);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15578);
        print_pairs(ptcts, 15578, MASK_15578, is_match_diff_15578);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15899);
        print_pairs(ptcts, 15899, MASK_15899, is_match_diff_15899);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15947);
        print_pairs(ptcts, 15947, MASK_15947, is_match_diff_15947);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15955);
        print_pairs(ptcts, 15955, MASK_15955, is_match_diff_15955);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15961);
        print_pairs(ptcts, 15961, MASK_15961, is_match_diff_15961);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_15962);
        print_pairs(ptcts, 15962, MASK_15962, is_match_diff_15962);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16011);
        print_pairs(ptcts, 16011, MASK_16011, is_match_diff_16011);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16019);
        print_pairs(ptcts, 16019, MASK_16019, is_match_diff_16019);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16025);
        print_pairs(ptcts, 16025, MASK_16025, is_match_diff_16025);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16026);
        print_pairs(ptcts, 16026, MASK_16026, is_match_diff_16026);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16067);
        print_pairs(ptcts, 16067, MASK_16067, is_match_diff_16067);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16074);
        print_pairs(ptcts, 16074, MASK_16074, is_match_diff_16074);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16081);
        print_pairs(ptcts, 16081, MASK_16081, is_match_diff_16081);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16082);
        print_pairs(ptcts, 16082, MASK_16082, is_match_diff_16082);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_16088);
        print_pairs(ptcts, 16088, MASK_16088, is_match_diff_16088);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_17278);
        print_pairs(ptcts, 17278, MASK_17278, is_match_diff_17278);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_17847);
        print_pairs(ptcts, 17847, MASK_17847, is_match_diff_17847);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_18139);
        print_pairs(ptcts, 18139, MASK_18139, is_match_diff_18139);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_18814);
        print_pairs(ptcts, 18814, MASK_18814, is_match_diff_18814);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_18871);
        print_pairs(ptcts, 18871, MASK_18871, is_match_diff_18871);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19070);
        print_pairs(ptcts, 19070, MASK_19070, is_match_diff_19070);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19163);
        print_pairs(ptcts, 19163, MASK_19163, is_match_diff_19163);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19262);
        print_pairs(ptcts, 19262, MASK_19262, is_match_diff_19262);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19294);
        print_pairs(ptcts, 19294, MASK_19294, is_match_diff_19294);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19310);
        print_pairs(ptcts, 19310, MASK_19310, is_match_diff_19310);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19318);
        print_pairs(ptcts, 19318, MASK_19318, is_match_diff_19318);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19322);
        print_pairs(ptcts, 19322, MASK_19322, is_match_diff_19322);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19324);
        print_pairs(ptcts, 19324, MASK_19324, is_match_diff_19324);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19639);
        print_pairs(ptcts, 19639, MASK_19639, is_match_diff_19639);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19675);
        print_pairs(ptcts, 19675, MASK_19675, is_match_diff_19675);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19767);
        print_pairs(ptcts, 19767, MASK_19767, is_match_diff_19767);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19863);
        print_pairs(ptcts, 19863, MASK_19863, is_match_diff_19863);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19879);
        print_pairs(ptcts, 19879, MASK_19879, is_match_diff_19879);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19891);
        print_pairs(ptcts, 19891, MASK_19891, is_match_diff_19891);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19893);
        print_pairs(ptcts, 19893, MASK_19893, is_match_diff_19893);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_19894);
        print_pairs(ptcts, 19894, MASK_19894, is_match_diff_19894);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20059);
        print_pairs(ptcts, 20059, MASK_20059, is_match_diff_20059);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20123);
        print_pairs(ptcts, 20123, MASK_20123, is_match_diff_20123);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20171);
        print_pairs(ptcts, 20171, MASK_20171, is_match_diff_20171);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20179);
        print_pairs(ptcts, 20179, MASK_20179, is_match_diff_20179);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20185);
        print_pairs(ptcts, 20185, MASK_20185, is_match_diff_20185);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20186);
        print_pairs(ptcts, 20186, MASK_20186, is_match_diff_20186);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_20862);
        print_pairs(ptcts, 20862, MASK_20862, is_match_diff_20862);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21118);
        print_pairs(ptcts, 21118, MASK_21118, is_match_diff_21118);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21211);
        print_pairs(ptcts, 21211, MASK_21211, is_match_diff_21211);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21310);
        print_pairs(ptcts, 21310, MASK_21310, is_match_diff_21310);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21342);
        print_pairs(ptcts, 21342, MASK_21342, is_match_diff_21342);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21358);
        print_pairs(ptcts, 21358, MASK_21358, is_match_diff_21358);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21366);
        print_pairs(ptcts, 21366, MASK_21366, is_match_diff_21366);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21370);
        print_pairs(ptcts, 21370, MASK_21370, is_match_diff_21370);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21372);
        print_pairs(ptcts, 21372, MASK_21372, is_match_diff_21372);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_21723);
        print_pairs(ptcts, 21723, MASK_21723, is_match_diff_21723);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22107);
        print_pairs(ptcts, 22107, MASK_22107, is_match_diff_22107);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22171);
        print_pairs(ptcts, 22171, MASK_22171, is_match_diff_22171);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22219);
        print_pairs(ptcts, 22219, MASK_22219, is_match_diff_22219);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22227);
        print_pairs(ptcts, 22227, MASK_22227, is_match_diff_22227);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22233);
        print_pairs(ptcts, 22233, MASK_22233, is_match_diff_22233);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22234);
        print_pairs(ptcts, 22234, MASK_22234, is_match_diff_22234);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22654);
        print_pairs(ptcts, 22654, MASK_22654, is_match_diff_22654);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22747);
        print_pairs(ptcts, 22747, MASK_22747, is_match_diff_22747);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22846);
        print_pairs(ptcts, 22846, MASK_22846, is_match_diff_22846);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22878);
        print_pairs(ptcts, 22878, MASK_22878, is_match_diff_22878);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22894);
        print_pairs(ptcts, 22894, MASK_22894, is_match_diff_22894);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22902);
        print_pairs(ptcts, 22902, MASK_22902, is_match_diff_22902);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22906);
        print_pairs(ptcts, 22906, MASK_22906, is_match_diff_22906);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_22908);
        print_pairs(ptcts, 22908, MASK_22908, is_match_diff_22908);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23102);
        print_pairs(ptcts, 23102, MASK_23102, is_match_diff_23102);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23150);
        print_pairs(ptcts, 23150, MASK_23150, is_match_diff_23150);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23158);
        print_pairs(ptcts, 23158, MASK_23158, is_match_diff_23158);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23164);
        print_pairs(ptcts, 23164, MASK_23164, is_match_diff_23164);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23195);
        print_pairs(ptcts, 23195, MASK_23195, is_match_diff_23195);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23243);
        print_pairs(ptcts, 23243, MASK_23243, is_match_diff_23243);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23251);
        print_pairs(ptcts, 23251, MASK_23251, is_match_diff_23251);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23257);
        print_pairs(ptcts, 23257, MASK_23257, is_match_diff_23257);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23326);
        print_pairs(ptcts, 23326, MASK_23326, is_match_diff_23326);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23342);
        print_pairs(ptcts, 23342, MASK_23342, is_match_diff_23342);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23350);
        print_pairs(ptcts, 23350, MASK_23350, is_match_diff_23350);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23354);
        print_pairs(ptcts, 23354, MASK_23354, is_match_diff_23354);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23356);
        print_pairs(ptcts, 23356, MASK_23356, is_match_diff_23356);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23374);
        print_pairs(ptcts, 23374, MASK_23374, is_match_diff_23374);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23382);
        print_pairs(ptcts, 23382, MASK_23382, is_match_diff_23382);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23388);
        print_pairs(ptcts, 23388, MASK_23388, is_match_diff_23388);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23398);
        print_pairs(ptcts, 23398, MASK_23398, is_match_diff_23398);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23402);
        print_pairs(ptcts, 23402, MASK_23402, is_match_diff_23402);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23404);
        print_pairs(ptcts, 23404, MASK_23404, is_match_diff_23404);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23410);
        print_pairs(ptcts, 23410, MASK_23410, is_match_diff_23410);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23412);
        print_pairs(ptcts, 23412, MASK_23412, is_match_diff_23412);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23416);
        print_pairs(ptcts, 23416, MASK_23416, is_match_diff_23416);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23643);
        print_pairs(ptcts, 23643, MASK_23643, is_match_diff_23643);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23707);
        print_pairs(ptcts, 23707, MASK_23707, is_match_diff_23707);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23755);
        print_pairs(ptcts, 23755, MASK_23755, is_match_diff_23755);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23763);
        print_pairs(ptcts, 23763, MASK_23763, is_match_diff_23763);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23769);
        print_pairs(ptcts, 23769, MASK_23769, is_match_diff_23769);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_23770);
        print_pairs(ptcts, 23770, MASK_23770, is_match_diff_23770);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24091);
        print_pairs(ptcts, 24091, MASK_24091, is_match_diff_24091);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24139);
        print_pairs(ptcts, 24139, MASK_24139, is_match_diff_24139);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24147);
        print_pairs(ptcts, 24147, MASK_24147, is_match_diff_24147);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24153);
        print_pairs(ptcts, 24153, MASK_24153, is_match_diff_24153);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24203);
        print_pairs(ptcts, 24203, MASK_24203, is_match_diff_24203);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24211);
        print_pairs(ptcts, 24211, MASK_24211, is_match_diff_24211);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24217);
        print_pairs(ptcts, 24217, MASK_24217, is_match_diff_24217);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24218);
        print_pairs(ptcts, 24218, MASK_24218, is_match_diff_24218);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24259);
        print_pairs(ptcts, 24259, MASK_24259, is_match_diff_24259);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24265);
        print_pairs(ptcts, 24265, MASK_24265, is_match_diff_24265);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24266);
        print_pairs(ptcts, 24266, MASK_24266, is_match_diff_24266);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24273);
        print_pairs(ptcts, 24273, MASK_24273, is_match_diff_24273);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24274);
        print_pairs(ptcts, 24274, MASK_24274, is_match_diff_24274);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_24280);
        print_pairs(ptcts, 24280, MASK_24280, is_match_diff_24280);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_25015);
        print_pairs(ptcts, 25015, MASK_25015, is_match_diff_25015);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_25307);
        print_pairs(ptcts, 25307, MASK_25307, is_match_diff_25307);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_25783);
        print_pairs(ptcts, 25783, MASK_25783, is_match_diff_25783);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_25819);
        print_pairs(ptcts, 25819, MASK_25819, is_match_diff_25819);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_25911);
        print_pairs(ptcts, 25911, MASK_25911, is_match_diff_25911);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26007);
        print_pairs(ptcts, 26007, MASK_26007, is_match_diff_26007);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26023);
        print_pairs(ptcts, 26023, MASK_26023, is_match_diff_26023);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26035);
        print_pairs(ptcts, 26035, MASK_26035, is_match_diff_26035);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26037);
        print_pairs(ptcts, 26037, MASK_26037, is_match_diff_26037);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26038);
        print_pairs(ptcts, 26038, MASK_26038, is_match_diff_26038);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26203);
        print_pairs(ptcts, 26203, MASK_26203, is_match_diff_26203);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26267);
        print_pairs(ptcts, 26267, MASK_26267, is_match_diff_26267);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26315);
        print_pairs(ptcts, 26315, MASK_26315, is_match_diff_26315);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26323);
        print_pairs(ptcts, 26323, MASK_26323, is_match_diff_26323);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26329);
        print_pairs(ptcts, 26329, MASK_26329, is_match_diff_26329);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26330);
        print_pairs(ptcts, 26330, MASK_26330, is_match_diff_26330);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26807);
        print_pairs(ptcts, 26807, MASK_26807, is_match_diff_26807);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26843);
        print_pairs(ptcts, 26843, MASK_26843, is_match_diff_26843);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_26935);
        print_pairs(ptcts, 26935, MASK_26935, is_match_diff_26935);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27031);
        print_pairs(ptcts, 27031, MASK_27031, is_match_diff_27031);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27047);
        print_pairs(ptcts, 27047, MASK_27047, is_match_diff_27047);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27059);
        print_pairs(ptcts, 27059, MASK_27059, is_match_diff_27059);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27061);
        print_pairs(ptcts, 27061, MASK_27061, is_match_diff_27061);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27062);
        print_pairs(ptcts, 27062, MASK_27062, is_match_diff_27062);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27227);
        print_pairs(ptcts, 27227, MASK_27227, is_match_diff_27227);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27291);
        print_pairs(ptcts, 27291, MASK_27291, is_match_diff_27291);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27339);
        print_pairs(ptcts, 27339, MASK_27339, is_match_diff_27339);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27347);
        print_pairs(ptcts, 27347, MASK_27347, is_match_diff_27347);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27353);
        print_pairs(ptcts, 27353, MASK_27353, is_match_diff_27353);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27354);
        print_pairs(ptcts, 27354, MASK_27354, is_match_diff_27354);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27703);
        print_pairs(ptcts, 27703, MASK_27703, is_match_diff_27703);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27739);
        print_pairs(ptcts, 27739, MASK_27739, is_match_diff_27739);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27815);
        print_pairs(ptcts, 27815, MASK_27815, is_match_diff_27815);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27829);
        print_pairs(ptcts, 27829, MASK_27829, is_match_diff_27829);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27830);
        print_pairs(ptcts, 27830, MASK_27830, is_match_diff_27830);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27851);
        print_pairs(ptcts, 27851, MASK_27851, is_match_diff_27851);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27865);
        print_pairs(ptcts, 27865, MASK_27865, is_match_diff_27865);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27866);
        print_pairs(ptcts, 27866, MASK_27866, is_match_diff_27866);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27927);
        print_pairs(ptcts, 27927, MASK_27927, is_match_diff_27927);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27943);
        print_pairs(ptcts, 27943, MASK_27943, is_match_diff_27943);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27955);
        print_pairs(ptcts, 27955, MASK_27955, is_match_diff_27955);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27957);
        print_pairs(ptcts, 27957, MASK_27957, is_match_diff_27957);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_27958);
        print_pairs(ptcts, 27958, MASK_27958, is_match_diff_27958);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28039);
        print_pairs(ptcts, 28039, MASK_28039, is_match_diff_28039);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28053);
        print_pairs(ptcts, 28053, MASK_28053, is_match_diff_28053);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28054);
        print_pairs(ptcts, 28054, MASK_28054, is_match_diff_28054);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28067);
        print_pairs(ptcts, 28067, MASK_28067, is_match_diff_28067);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28069);
        print_pairs(ptcts, 28069, MASK_28069, is_match_diff_28069);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28070);
        print_pairs(ptcts, 28070, MASK_28070, is_match_diff_28070);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28081);
        print_pairs(ptcts, 28081, MASK_28081, is_match_diff_28081);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28082);
        print_pairs(ptcts, 28082, MASK_28082, is_match_diff_28082);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28084);
        print_pairs(ptcts, 28084, MASK_28084, is_match_diff_28084);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28187);
        print_pairs(ptcts, 28187, MASK_28187, is_match_diff_28187);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28235);
        print_pairs(ptcts, 28235, MASK_28235, is_match_diff_28235);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28243);
        print_pairs(ptcts, 28243, MASK_28243, is_match_diff_28243);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28249);
        print_pairs(ptcts, 28249, MASK_28249, is_match_diff_28249);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28250);
        print_pairs(ptcts, 28250, MASK_28250, is_match_diff_28250);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28299);
        print_pairs(ptcts, 28299, MASK_28299, is_match_diff_28299);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28313);
        print_pairs(ptcts, 28313, MASK_28313, is_match_diff_28313);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28314);
        print_pairs(ptcts, 28314, MASK_28314, is_match_diff_28314);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28355);
        print_pairs(ptcts, 28355, MASK_28355, is_match_diff_28355);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28361);
        print_pairs(ptcts, 28361, MASK_28361, is_match_diff_28361);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28362);
        print_pairs(ptcts, 28362, MASK_28362, is_match_diff_28362);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28369);
        print_pairs(ptcts, 28369, MASK_28369, is_match_diff_28369);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28370);
        print_pairs(ptcts, 28370, MASK_28370, is_match_diff_28370);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28376);
        print_pairs(ptcts, 28376, MASK_28376, is_match_diff_28376);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_28891);
        print_pairs(ptcts, 28891, MASK_28891, is_match_diff_28891);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29275);
        print_pairs(ptcts, 29275, MASK_29275, is_match_diff_29275);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29339);
        print_pairs(ptcts, 29339, MASK_29339, is_match_diff_29339);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29387);
        print_pairs(ptcts, 29387, MASK_29387, is_match_diff_29387);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29395);
        print_pairs(ptcts, 29395, MASK_29395, is_match_diff_29395);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29401);
        print_pairs(ptcts, 29401, MASK_29401, is_match_diff_29401);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29402);
        print_pairs(ptcts, 29402, MASK_29402, is_match_diff_29402);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29787);
        print_pairs(ptcts, 29787, MASK_29787, is_match_diff_29787);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29851);
        print_pairs(ptcts, 29851, MASK_29851, is_match_diff_29851);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29899);
        print_pairs(ptcts, 29899, MASK_29899, is_match_diff_29899);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29907);
        print_pairs(ptcts, 29907, MASK_29907, is_match_diff_29907);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29913);
        print_pairs(ptcts, 29913, MASK_29913, is_match_diff_29913);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_29914);
        print_pairs(ptcts, 29914, MASK_29914, is_match_diff_29914);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30235);
        print_pairs(ptcts, 30235, MASK_30235, is_match_diff_30235);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30283);
        print_pairs(ptcts, 30283, MASK_30283, is_match_diff_30283);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30291);
        print_pairs(ptcts, 30291, MASK_30291, is_match_diff_30291);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30297);
        print_pairs(ptcts, 30297, MASK_30297, is_match_diff_30297);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30298);
        print_pairs(ptcts, 30298, MASK_30298, is_match_diff_30298);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30347);
        print_pairs(ptcts, 30347, MASK_30347, is_match_diff_30347);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30355);
        print_pairs(ptcts, 30355, MASK_30355, is_match_diff_30355);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30361);
        print_pairs(ptcts, 30361, MASK_30361, is_match_diff_30361);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30362);
        print_pairs(ptcts, 30362, MASK_30362, is_match_diff_30362);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30403);
        print_pairs(ptcts, 30403, MASK_30403, is_match_diff_30403);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30410);
        print_pairs(ptcts, 30410, MASK_30410, is_match_diff_30410);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30417);
        print_pairs(ptcts, 30417, MASK_30417, is_match_diff_30417);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30418);
        print_pairs(ptcts, 30418, MASK_30418, is_match_diff_30418);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30424);
        print_pairs(ptcts, 30424, MASK_30424, is_match_diff_30424);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30811);
        print_pairs(ptcts, 30811, MASK_30811, is_match_diff_30811);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30875);
        print_pairs(ptcts, 30875, MASK_30875, is_match_diff_30875);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30923);
        print_pairs(ptcts, 30923, MASK_30923, is_match_diff_30923);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30931);
        print_pairs(ptcts, 30931, MASK_30931, is_match_diff_30931);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30937);
        print_pairs(ptcts, 30937, MASK_30937, is_match_diff_30937);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_30938);
        print_pairs(ptcts, 30938, MASK_30938, is_match_diff_30938);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31259);
        print_pairs(ptcts, 31259, MASK_31259, is_match_diff_31259);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31307);
        print_pairs(ptcts, 31307, MASK_31307, is_match_diff_31307);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31315);
        print_pairs(ptcts, 31315, MASK_31315, is_match_diff_31315);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31321);
        print_pairs(ptcts, 31321, MASK_31321, is_match_diff_31321);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31371);
        print_pairs(ptcts, 31371, MASK_31371, is_match_diff_31371);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31379);
        print_pairs(ptcts, 31379, MASK_31379, is_match_diff_31379);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31385);
        print_pairs(ptcts, 31385, MASK_31385, is_match_diff_31385);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31386);
        print_pairs(ptcts, 31386, MASK_31386, is_match_diff_31386);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31427);
        print_pairs(ptcts, 31427, MASK_31427, is_match_diff_31427);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31433);
        print_pairs(ptcts, 31433, MASK_31433, is_match_diff_31433);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31434);
        print_pairs(ptcts, 31434, MASK_31434, is_match_diff_31434);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31441);
        print_pairs(ptcts, 31441, MASK_31441, is_match_diff_31441);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31442);
        print_pairs(ptcts, 31442, MASK_31442, is_match_diff_31442);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31448);
        print_pairs(ptcts, 31448, MASK_31448, is_match_diff_31448);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31771);
        print_pairs(ptcts, 31771, MASK_31771, is_match_diff_31771);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31819);
        print_pairs(ptcts, 31819, MASK_31819, is_match_diff_31819);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31827);
        print_pairs(ptcts, 31827, MASK_31827, is_match_diff_31827);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31833);
        print_pairs(ptcts, 31833, MASK_31833, is_match_diff_31833);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31834);
        print_pairs(ptcts, 31834, MASK_31834, is_match_diff_31834);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31883);
        print_pairs(ptcts, 31883, MASK_31883, is_match_diff_31883);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31897);
        print_pairs(ptcts, 31897, MASK_31897, is_match_diff_31897);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31898);
        print_pairs(ptcts, 31898, MASK_31898, is_match_diff_31898);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31939);
        print_pairs(ptcts, 31939, MASK_31939, is_match_diff_31939);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31945);
        print_pairs(ptcts, 31945, MASK_31945, is_match_diff_31945);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31946);
        print_pairs(ptcts, 31946, MASK_31946, is_match_diff_31946);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31953);
        print_pairs(ptcts, 31953, MASK_31953, is_match_diff_31953);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31954);
        print_pairs(ptcts, 31954, MASK_31954, is_match_diff_31954);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_31960);
        print_pairs(ptcts, 31960, MASK_31960, is_match_diff_31960);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32267);
        print_pairs(ptcts, 32267, MASK_32267, is_match_diff_32267);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32275);
        print_pairs(ptcts, 32275, MASK_32275, is_match_diff_32275);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32281);
        print_pairs(ptcts, 32281, MASK_32281, is_match_diff_32281);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32282);
        print_pairs(ptcts, 32282, MASK_32282, is_match_diff_32282);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32323);
        print_pairs(ptcts, 32323, MASK_32323, is_match_diff_32323);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32329);
        print_pairs(ptcts, 32329, MASK_32329, is_match_diff_32329);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32330);
        print_pairs(ptcts, 32330, MASK_32330, is_match_diff_32330);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32337);
        print_pairs(ptcts, 32337, MASK_32337, is_match_diff_32337);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32338);
        print_pairs(ptcts, 32338, MASK_32338, is_match_diff_32338);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32344);
        print_pairs(ptcts, 32344, MASK_32344, is_match_diff_32344);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32387);
        print_pairs(ptcts, 32387, MASK_32387, is_match_diff_32387);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32393);
        print_pairs(ptcts, 32393, MASK_32393, is_match_diff_32393);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32394);
        print_pairs(ptcts, 32394, MASK_32394, is_match_diff_32394);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32401);
        print_pairs(ptcts, 32401, MASK_32401, is_match_diff_32401);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32402);
        print_pairs(ptcts, 32402, MASK_32402, is_match_diff_32402);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32408);
        print_pairs(ptcts, 32408, MASK_32408, is_match_diff_32408);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32449);
        print_pairs(ptcts, 32449, MASK_32449, is_match_diff_32449);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32450);
        print_pairs(ptcts, 32450, MASK_32450, is_match_diff_32450);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32456);
        print_pairs(ptcts, 32456, MASK_32456, is_match_diff_32456);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_32464);
        print_pairs(ptcts, 32464, MASK_32464, is_match_diff_32464);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_33662);
        print_pairs(ptcts, 33662, MASK_33662, is_match_diff_33662);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_33773);
        print_pairs(ptcts, 33773, MASK_33773, is_match_diff_33773);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34231);
        print_pairs(ptcts, 34231, MASK_34231, is_match_diff_34231);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34285);
        print_pairs(ptcts, 34285, MASK_34285, is_match_diff_34285);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34541);
        print_pairs(ptcts, 34541, MASK_34541, is_match_diff_34541);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34669);
        print_pairs(ptcts, 34669, MASK_34669, is_match_diff_34669);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34733);
        print_pairs(ptcts, 34733, MASK_34733, is_match_diff_34733);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34765);
        print_pairs(ptcts, 34765, MASK_34765, is_match_diff_34765);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34789);
        print_pairs(ptcts, 34789, MASK_34789, is_match_diff_34789);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34793);
        print_pairs(ptcts, 34793, MASK_34793, is_match_diff_34793);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_34796);
        print_pairs(ptcts, 34796, MASK_34796, is_match_diff_34796);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35198);
        print_pairs(ptcts, 35198, MASK_35198, is_match_diff_35198);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35255);
        print_pairs(ptcts, 35255, MASK_35255, is_match_diff_35255);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35454);
        print_pairs(ptcts, 35454, MASK_35454, is_match_diff_35454);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35646);
        print_pairs(ptcts, 35646, MASK_35646, is_match_diff_35646);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35678);
        print_pairs(ptcts, 35678, MASK_35678, is_match_diff_35678);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35694);
        print_pairs(ptcts, 35694, MASK_35694, is_match_diff_35694);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35702);
        print_pairs(ptcts, 35702, MASK_35702, is_match_diff_35702);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35706);
        print_pairs(ptcts, 35706, MASK_35706, is_match_diff_35706);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_35708);
        print_pairs(ptcts, 35708, MASK_35708, is_match_diff_35708);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36023);
        print_pairs(ptcts, 36023, MASK_36023, is_match_diff_36023);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36151);
        print_pairs(ptcts, 36151, MASK_36151, is_match_diff_36151);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36247);
        print_pairs(ptcts, 36247, MASK_36247, is_match_diff_36247);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36263);
        print_pairs(ptcts, 36263, MASK_36263, is_match_diff_36263);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36275);
        print_pairs(ptcts, 36275, MASK_36275, is_match_diff_36275);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36277);
        print_pairs(ptcts, 36277, MASK_36277, is_match_diff_36277);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_36278);
        print_pairs(ptcts, 36278, MASK_36278, is_match_diff_36278);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37246);
        print_pairs(ptcts, 37246, MASK_37246, is_match_diff_37246);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37357);
        print_pairs(ptcts, 37357, MASK_37357, is_match_diff_37357);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37502);
        print_pairs(ptcts, 37502, MASK_37502, is_match_diff_37502);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37613);
        print_pairs(ptcts, 37613, MASK_37613, is_match_diff_37613);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37694);
        print_pairs(ptcts, 37694, MASK_37694, is_match_diff_37694);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37726);
        print_pairs(ptcts, 37726, MASK_37726, is_match_diff_37726);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37750);
        print_pairs(ptcts, 37750, MASK_37750, is_match_diff_37750);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37754);
        print_pairs(ptcts, 37754, MASK_37754, is_match_diff_37754);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37805);
        print_pairs(ptcts, 37805, MASK_37805, is_match_diff_37805);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37837);
        print_pairs(ptcts, 37837, MASK_37837, is_match_diff_37837);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37861);
        print_pairs(ptcts, 37861, MASK_37861, is_match_diff_37861);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_37865);
        print_pairs(ptcts, 37865, MASK_37865, is_match_diff_37865);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38125);
        print_pairs(ptcts, 38125, MASK_38125, is_match_diff_38125);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38253);
        print_pairs(ptcts, 38253, MASK_38253, is_match_diff_38253);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38317);
        print_pairs(ptcts, 38317, MASK_38317, is_match_diff_38317);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38349);
        print_pairs(ptcts, 38349, MASK_38349, is_match_diff_38349);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38373);
        print_pairs(ptcts, 38373, MASK_38373, is_match_diff_38373);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38377);
        print_pairs(ptcts, 38377, MASK_38377, is_match_diff_38377);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38380);
        print_pairs(ptcts, 38380, MASK_38380, is_match_diff_38380);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38509);
        print_pairs(ptcts, 38509, MASK_38509, is_match_diff_38509);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38573);
        print_pairs(ptcts, 38573, MASK_38573, is_match_diff_38573);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38605);
        print_pairs(ptcts, 38605, MASK_38605, is_match_diff_38605);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38629);
        print_pairs(ptcts, 38629, MASK_38629, is_match_diff_38629);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38633);
        print_pairs(ptcts, 38633, MASK_38633, is_match_diff_38633);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38636);
        print_pairs(ptcts, 38636, MASK_38636, is_match_diff_38636);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38701);
        print_pairs(ptcts, 38701, MASK_38701, is_match_diff_38701);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38733);
        print_pairs(ptcts, 38733, MASK_38733, is_match_diff_38733);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38757);
        print_pairs(ptcts, 38757, MASK_38757, is_match_diff_38757);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38761);
        print_pairs(ptcts, 38761, MASK_38761, is_match_diff_38761);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38797);
        print_pairs(ptcts, 38797, MASK_38797, is_match_diff_38797);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38821);
        print_pairs(ptcts, 38821, MASK_38821, is_match_diff_38821);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38825);
        print_pairs(ptcts, 38825, MASK_38825, is_match_diff_38825);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38828);
        print_pairs(ptcts, 38828, MASK_38828, is_match_diff_38828);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38853);
        print_pairs(ptcts, 38853, MASK_38853, is_match_diff_38853);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38857);
        print_pairs(ptcts, 38857, MASK_38857, is_match_diff_38857);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38860);
        print_pairs(ptcts, 38860, MASK_38860, is_match_diff_38860);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38881);
        print_pairs(ptcts, 38881, MASK_38881, is_match_diff_38881);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38884);
        print_pairs(ptcts, 38884, MASK_38884, is_match_diff_38884);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_38888);
        print_pairs(ptcts, 38888, MASK_38888, is_match_diff_38888);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39038);
        print_pairs(ptcts, 39038, MASK_39038, is_match_diff_39038);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39230);
        print_pairs(ptcts, 39230, MASK_39230, is_match_diff_39230);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39262);
        print_pairs(ptcts, 39262, MASK_39262, is_match_diff_39262);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39278);
        print_pairs(ptcts, 39278, MASK_39278, is_match_diff_39278);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39286);
        print_pairs(ptcts, 39286, MASK_39286, is_match_diff_39286);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39290);
        print_pairs(ptcts, 39290, MASK_39290, is_match_diff_39290);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39292);
        print_pairs(ptcts, 39292, MASK_39292, is_match_diff_39292);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39486);
        print_pairs(ptcts, 39486, MASK_39486, is_match_diff_39486);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39518);
        print_pairs(ptcts, 39518, MASK_39518, is_match_diff_39518);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39534);
        print_pairs(ptcts, 39534, MASK_39534, is_match_diff_39534);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39542);
        print_pairs(ptcts, 39542, MASK_39542, is_match_diff_39542);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39546);
        print_pairs(ptcts, 39546, MASK_39546, is_match_diff_39546);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39548);
        print_pairs(ptcts, 39548, MASK_39548, is_match_diff_39548);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39710);
        print_pairs(ptcts, 39710, MASK_39710, is_match_diff_39710);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39726);
        print_pairs(ptcts, 39726, MASK_39726, is_match_diff_39726);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39734);
        print_pairs(ptcts, 39734, MASK_39734, is_match_diff_39734);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39738);
        print_pairs(ptcts, 39738, MASK_39738, is_match_diff_39738);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39740);
        print_pairs(ptcts, 39740, MASK_39740, is_match_diff_39740);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39758);
        print_pairs(ptcts, 39758, MASK_39758, is_match_diff_39758);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39766);
        print_pairs(ptcts, 39766, MASK_39766, is_match_diff_39766);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39770);
        print_pairs(ptcts, 39770, MASK_39770, is_match_diff_39770);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39772);
        print_pairs(ptcts, 39772, MASK_39772, is_match_diff_39772);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39782);
        print_pairs(ptcts, 39782, MASK_39782, is_match_diff_39782);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39786);
        print_pairs(ptcts, 39786, MASK_39786, is_match_diff_39786);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39794);
        print_pairs(ptcts, 39794, MASK_39794, is_match_diff_39794);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39796);
        print_pairs(ptcts, 39796, MASK_39796, is_match_diff_39796);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_39800);
        print_pairs(ptcts, 39800, MASK_39800, is_match_diff_39800);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41399);
        print_pairs(ptcts, 41399, MASK_41399, is_match_diff_41399);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41453);
        print_pairs(ptcts, 41453, MASK_41453, is_match_diff_41453);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41709);
        print_pairs(ptcts, 41709, MASK_41709, is_match_diff_41709);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41837);
        print_pairs(ptcts, 41837, MASK_41837, is_match_diff_41837);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41901);
        print_pairs(ptcts, 41901, MASK_41901, is_match_diff_41901);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41933);
        print_pairs(ptcts, 41933, MASK_41933, is_match_diff_41933);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41957);
        print_pairs(ptcts, 41957, MASK_41957, is_match_diff_41957);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41961);
        print_pairs(ptcts, 41961, MASK_41961, is_match_diff_41961);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_41964);
        print_pairs(ptcts, 41964, MASK_41964, is_match_diff_41964);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42167);
        print_pairs(ptcts, 42167, MASK_42167, is_match_diff_42167);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42221);
        print_pairs(ptcts, 42221, MASK_42221, is_match_diff_42221);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42295);
        print_pairs(ptcts, 42295, MASK_42295, is_match_diff_42295);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42349);
        print_pairs(ptcts, 42349, MASK_42349, is_match_diff_42349);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42391);
        print_pairs(ptcts, 42391, MASK_42391, is_match_diff_42391);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42419);
        print_pairs(ptcts, 42419, MASK_42419, is_match_diff_42419);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42422);
        print_pairs(ptcts, 42422, MASK_42422, is_match_diff_42422);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42445);
        print_pairs(ptcts, 42445, MASK_42445, is_match_diff_42445);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42473);
        print_pairs(ptcts, 42473, MASK_42473, is_match_diff_42473);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42476);
        print_pairs(ptcts, 42476, MASK_42476, is_match_diff_42476);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42605);
        print_pairs(ptcts, 42605, MASK_42605, is_match_diff_42605);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42669);
        print_pairs(ptcts, 42669, MASK_42669, is_match_diff_42669);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42701);
        print_pairs(ptcts, 42701, MASK_42701, is_match_diff_42701);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42725);
        print_pairs(ptcts, 42725, MASK_42725, is_match_diff_42725);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42729);
        print_pairs(ptcts, 42729, MASK_42729, is_match_diff_42729);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42732);
        print_pairs(ptcts, 42732, MASK_42732, is_match_diff_42732);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42797);
        print_pairs(ptcts, 42797, MASK_42797, is_match_diff_42797);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42829);
        print_pairs(ptcts, 42829, MASK_42829, is_match_diff_42829);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42853);
        print_pairs(ptcts, 42853, MASK_42853, is_match_diff_42853);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42857);
        print_pairs(ptcts, 42857, MASK_42857, is_match_diff_42857);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42860);
        print_pairs(ptcts, 42860, MASK_42860, is_match_diff_42860);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42893);
        print_pairs(ptcts, 42893, MASK_42893, is_match_diff_42893);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42921);
        print_pairs(ptcts, 42921, MASK_42921, is_match_diff_42921);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42924);
        print_pairs(ptcts, 42924, MASK_42924, is_match_diff_42924);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42949);
        print_pairs(ptcts, 42949, MASK_42949, is_match_diff_42949);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42953);
        print_pairs(ptcts, 42953, MASK_42953, is_match_diff_42953);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42956);
        print_pairs(ptcts, 42956, MASK_42956, is_match_diff_42956);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42977);
        print_pairs(ptcts, 42977, MASK_42977, is_match_diff_42977);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42980);
        print_pairs(ptcts, 42980, MASK_42980, is_match_diff_42980);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_42984);
        print_pairs(ptcts, 42984, MASK_42984, is_match_diff_42984);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43191);
        print_pairs(ptcts, 43191, MASK_43191, is_match_diff_43191);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43319);
        print_pairs(ptcts, 43319, MASK_43319, is_match_diff_43319);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43415);
        print_pairs(ptcts, 43415, MASK_43415, is_match_diff_43415);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43431);
        print_pairs(ptcts, 43431, MASK_43431, is_match_diff_43431);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43443);
        print_pairs(ptcts, 43443, MASK_43443, is_match_diff_43443);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43445);
        print_pairs(ptcts, 43445, MASK_43445, is_match_diff_43445);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_43446);
        print_pairs(ptcts, 43446, MASK_43446, is_match_diff_43446);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44087);
        print_pairs(ptcts, 44087, MASK_44087, is_match_diff_44087);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44183);
        print_pairs(ptcts, 44183, MASK_44183, is_match_diff_44183);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44199);
        print_pairs(ptcts, 44199, MASK_44199, is_match_diff_44199);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44211);
        print_pairs(ptcts, 44211, MASK_44211, is_match_diff_44211);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44213);
        print_pairs(ptcts, 44213, MASK_44213, is_match_diff_44213);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44214);
        print_pairs(ptcts, 44214, MASK_44214, is_match_diff_44214);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44311);
        print_pairs(ptcts, 44311, MASK_44311, is_match_diff_44311);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44327);
        print_pairs(ptcts, 44327, MASK_44327, is_match_diff_44327);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44339);
        print_pairs(ptcts, 44339, MASK_44339, is_match_diff_44339);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44341);
        print_pairs(ptcts, 44341, MASK_44341, is_match_diff_44341);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44342);
        print_pairs(ptcts, 44342, MASK_44342, is_match_diff_44342);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44423);
        print_pairs(ptcts, 44423, MASK_44423, is_match_diff_44423);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44435);
        print_pairs(ptcts, 44435, MASK_44435, is_match_diff_44435);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44437);
        print_pairs(ptcts, 44437, MASK_44437, is_match_diff_44437);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44438);
        print_pairs(ptcts, 44438, MASK_44438, is_match_diff_44438);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44451);
        print_pairs(ptcts, 44451, MASK_44451, is_match_diff_44451);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44454);
        print_pairs(ptcts, 44454, MASK_44454, is_match_diff_44454);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44465);
        print_pairs(ptcts, 44465, MASK_44465, is_match_diff_44465);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44466);
        print_pairs(ptcts, 44466, MASK_44466, is_match_diff_44466);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_44468);
        print_pairs(ptcts, 44468, MASK_44468, is_match_diff_44468);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45293);
        print_pairs(ptcts, 45293, MASK_45293, is_match_diff_45293);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45421);
        print_pairs(ptcts, 45421, MASK_45421, is_match_diff_45421);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45485);
        print_pairs(ptcts, 45485, MASK_45485, is_match_diff_45485);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45517);
        print_pairs(ptcts, 45517, MASK_45517, is_match_diff_45517);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45541);
        print_pairs(ptcts, 45541, MASK_45541, is_match_diff_45541);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45545);
        print_pairs(ptcts, 45545, MASK_45545, is_match_diff_45545);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45548);
        print_pairs(ptcts, 45548, MASK_45548, is_match_diff_45548);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45677);
        print_pairs(ptcts, 45677, MASK_45677, is_match_diff_45677);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45741);
        print_pairs(ptcts, 45741, MASK_45741, is_match_diff_45741);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45773);
        print_pairs(ptcts, 45773, MASK_45773, is_match_diff_45773);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45797);
        print_pairs(ptcts, 45797, MASK_45797, is_match_diff_45797);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45801);
        print_pairs(ptcts, 45801, MASK_45801, is_match_diff_45801);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45804);
        print_pairs(ptcts, 45804, MASK_45804, is_match_diff_45804);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45869);
        print_pairs(ptcts, 45869, MASK_45869, is_match_diff_45869);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45901);
        print_pairs(ptcts, 45901, MASK_45901, is_match_diff_45901);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45925);
        print_pairs(ptcts, 45925, MASK_45925, is_match_diff_45925);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45929);
        print_pairs(ptcts, 45929, MASK_45929, is_match_diff_45929);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45965);
        print_pairs(ptcts, 45965, MASK_45965, is_match_diff_45965);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45989);
        print_pairs(ptcts, 45989, MASK_45989, is_match_diff_45989);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45993);
        print_pairs(ptcts, 45993, MASK_45993, is_match_diff_45993);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_45996);
        print_pairs(ptcts, 45996, MASK_45996, is_match_diff_45996);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46021);
        print_pairs(ptcts, 46021, MASK_46021, is_match_diff_46021);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46025);
        print_pairs(ptcts, 46025, MASK_46025, is_match_diff_46025);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46028);
        print_pairs(ptcts, 46028, MASK_46028, is_match_diff_46028);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46049);
        print_pairs(ptcts, 46049, MASK_46049, is_match_diff_46049);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46052);
        print_pairs(ptcts, 46052, MASK_46052, is_match_diff_46052);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46056);
        print_pairs(ptcts, 46056, MASK_46056, is_match_diff_46056);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46189);
        print_pairs(ptcts, 46189, MASK_46189, is_match_diff_46189);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46253);
        print_pairs(ptcts, 46253, MASK_46253, is_match_diff_46253);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46285);
        print_pairs(ptcts, 46285, MASK_46285, is_match_diff_46285);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46309);
        print_pairs(ptcts, 46309, MASK_46309, is_match_diff_46309);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46313);
        print_pairs(ptcts, 46313, MASK_46313, is_match_diff_46313);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46316);
        print_pairs(ptcts, 46316, MASK_46316, is_match_diff_46316);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46381);
        print_pairs(ptcts, 46381, MASK_46381, is_match_diff_46381);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46413);
        print_pairs(ptcts, 46413, MASK_46413, is_match_diff_46413);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46437);
        print_pairs(ptcts, 46437, MASK_46437, is_match_diff_46437);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46441);
        print_pairs(ptcts, 46441, MASK_46441, is_match_diff_46441);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46444);
        print_pairs(ptcts, 46444, MASK_46444, is_match_diff_46444);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46477);
        print_pairs(ptcts, 46477, MASK_46477, is_match_diff_46477);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46505);
        print_pairs(ptcts, 46505, MASK_46505, is_match_diff_46505);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46508);
        print_pairs(ptcts, 46508, MASK_46508, is_match_diff_46508);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46533);
        print_pairs(ptcts, 46533, MASK_46533, is_match_diff_46533);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46537);
        print_pairs(ptcts, 46537, MASK_46537, is_match_diff_46537);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46540);
        print_pairs(ptcts, 46540, MASK_46540, is_match_diff_46540);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46561);
        print_pairs(ptcts, 46561, MASK_46561, is_match_diff_46561);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46564);
        print_pairs(ptcts, 46564, MASK_46564, is_match_diff_46564);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46568);
        print_pairs(ptcts, 46568, MASK_46568, is_match_diff_46568);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46637);
        print_pairs(ptcts, 46637, MASK_46637, is_match_diff_46637);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46669);
        print_pairs(ptcts, 46669, MASK_46669, is_match_diff_46669);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46693);
        print_pairs(ptcts, 46693, MASK_46693, is_match_diff_46693);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46697);
        print_pairs(ptcts, 46697, MASK_46697, is_match_diff_46697);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46700);
        print_pairs(ptcts, 46700, MASK_46700, is_match_diff_46700);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46733);
        print_pairs(ptcts, 46733, MASK_46733, is_match_diff_46733);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46757);
        print_pairs(ptcts, 46757, MASK_46757, is_match_diff_46757);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46761);
        print_pairs(ptcts, 46761, MASK_46761, is_match_diff_46761);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46764);
        print_pairs(ptcts, 46764, MASK_46764, is_match_diff_46764);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46789);
        print_pairs(ptcts, 46789, MASK_46789, is_match_diff_46789);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46796);
        print_pairs(ptcts, 46796, MASK_46796, is_match_diff_46796);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46817);
        print_pairs(ptcts, 46817, MASK_46817, is_match_diff_46817);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46820);
        print_pairs(ptcts, 46820, MASK_46820, is_match_diff_46820);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46824);
        print_pairs(ptcts, 46824, MASK_46824, is_match_diff_46824);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46861);
        print_pairs(ptcts, 46861, MASK_46861, is_match_diff_46861);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46885);
        print_pairs(ptcts, 46885, MASK_46885, is_match_diff_46885);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46889);
        print_pairs(ptcts, 46889, MASK_46889, is_match_diff_46889);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46892);
        print_pairs(ptcts, 46892, MASK_46892, is_match_diff_46892);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46917);
        print_pairs(ptcts, 46917, MASK_46917, is_match_diff_46917);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46921);
        print_pairs(ptcts, 46921, MASK_46921, is_match_diff_46921);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46924);
        print_pairs(ptcts, 46924, MASK_46924, is_match_diff_46924);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46945);
        print_pairs(ptcts, 46945, MASK_46945, is_match_diff_46945);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46948);
        print_pairs(ptcts, 46948, MASK_46948, is_match_diff_46948);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46952);
        print_pairs(ptcts, 46952, MASK_46952, is_match_diff_46952);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46981);
        print_pairs(ptcts, 46981, MASK_46981, is_match_diff_46981);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46985);
        print_pairs(ptcts, 46985, MASK_46985, is_match_diff_46985);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_46988);
        print_pairs(ptcts, 46988, MASK_46988, is_match_diff_46988);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47009);
        print_pairs(ptcts, 47009, MASK_47009, is_match_diff_47009);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47012);
        print_pairs(ptcts, 47012, MASK_47012, is_match_diff_47012);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47016);
        print_pairs(ptcts, 47016, MASK_47016, is_match_diff_47016);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47041);
        print_pairs(ptcts, 47041, MASK_47041, is_match_diff_47041);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47044);
        print_pairs(ptcts, 47044, MASK_47044, is_match_diff_47044);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47048);
        print_pairs(ptcts, 47048, MASK_47048, is_match_diff_47048);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_47072);
        print_pairs(ptcts, 47072, MASK_47072, is_match_diff_47072);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_49534);
        print_pairs(ptcts, 49534, MASK_49534, is_match_diff_49534);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_49591);
        print_pairs(ptcts, 49591, MASK_49591, is_match_diff_49591);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_49790);
        print_pairs(ptcts, 49790, MASK_49790, is_match_diff_49790);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_49982);
        print_pairs(ptcts, 49982, MASK_49982, is_match_diff_49982);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50014);
        print_pairs(ptcts, 50014, MASK_50014, is_match_diff_50014);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50030);
        print_pairs(ptcts, 50030, MASK_50030, is_match_diff_50030);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50038);
        print_pairs(ptcts, 50038, MASK_50038, is_match_diff_50038);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50042);
        print_pairs(ptcts, 50042, MASK_50042, is_match_diff_50042);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50044);
        print_pairs(ptcts, 50044, MASK_50044, is_match_diff_50044);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50359);
        print_pairs(ptcts, 50359, MASK_50359, is_match_diff_50359);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50487);
        print_pairs(ptcts, 50487, MASK_50487, is_match_diff_50487);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50583);
        print_pairs(ptcts, 50583, MASK_50583, is_match_diff_50583);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50599);
        print_pairs(ptcts, 50599, MASK_50599, is_match_diff_50599);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50611);
        print_pairs(ptcts, 50611, MASK_50611, is_match_diff_50611);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50613);
        print_pairs(ptcts, 50613, MASK_50613, is_match_diff_50613);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_50614);
        print_pairs(ptcts, 50614, MASK_50614, is_match_diff_50614);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51326);
        print_pairs(ptcts, 51326, MASK_51326, is_match_diff_51326);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51383);
        print_pairs(ptcts, 51383, MASK_51383, is_match_diff_51383);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51550);
        print_pairs(ptcts, 51550, MASK_51550, is_match_diff_51550);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51566);
        print_pairs(ptcts, 51566, MASK_51566, is_match_diff_51566);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51578);
        print_pairs(ptcts, 51578, MASK_51578, is_match_diff_51578);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51580);
        print_pairs(ptcts, 51580, MASK_51580, is_match_diff_51580);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51607);
        print_pairs(ptcts, 51607, MASK_51607, is_match_diff_51607);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51623);
        print_pairs(ptcts, 51623, MASK_51623, is_match_diff_51623);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51635);
        print_pairs(ptcts, 51635, MASK_51635, is_match_diff_51635);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51637);
        print_pairs(ptcts, 51637, MASK_51637, is_match_diff_51637);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51774);
        print_pairs(ptcts, 51774, MASK_51774, is_match_diff_51774);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51806);
        print_pairs(ptcts, 51806, MASK_51806, is_match_diff_51806);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51822);
        print_pairs(ptcts, 51822, MASK_51822, is_match_diff_51822);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51830);
        print_pairs(ptcts, 51830, MASK_51830, is_match_diff_51830);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51834);
        print_pairs(ptcts, 51834, MASK_51834, is_match_diff_51834);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51836);
        print_pairs(ptcts, 51836, MASK_51836, is_match_diff_51836);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_51998);
        print_pairs(ptcts, 51998, MASK_51998, is_match_diff_51998);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52014);
        print_pairs(ptcts, 52014, MASK_52014, is_match_diff_52014);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52026);
        print_pairs(ptcts, 52026, MASK_52026, is_match_diff_52026);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52028);
        print_pairs(ptcts, 52028, MASK_52028, is_match_diff_52028);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52046);
        print_pairs(ptcts, 52046, MASK_52046, is_match_diff_52046);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52054);
        print_pairs(ptcts, 52054, MASK_52054, is_match_diff_52054);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52058);
        print_pairs(ptcts, 52058, MASK_52058, is_match_diff_52058);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52060);
        print_pairs(ptcts, 52060, MASK_52060, is_match_diff_52060);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52070);
        print_pairs(ptcts, 52070, MASK_52070, is_match_diff_52070);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52074);
        print_pairs(ptcts, 52074, MASK_52074, is_match_diff_52074);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52076);
        print_pairs(ptcts, 52076, MASK_52076, is_match_diff_52076);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52082);
        print_pairs(ptcts, 52082, MASK_52082, is_match_diff_52082);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52084);
        print_pairs(ptcts, 52084, MASK_52084, is_match_diff_52084);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52088);
        print_pairs(ptcts, 52088, MASK_52088, is_match_diff_52088);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52279);
        print_pairs(ptcts, 52279, MASK_52279, is_match_diff_52279);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52375);
        print_pairs(ptcts, 52375, MASK_52375, is_match_diff_52375);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52391);
        print_pairs(ptcts, 52391, MASK_52391, is_match_diff_52391);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52403);
        print_pairs(ptcts, 52403, MASK_52403, is_match_diff_52403);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52405);
        print_pairs(ptcts, 52405, MASK_52405, is_match_diff_52405);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52406);
        print_pairs(ptcts, 52406, MASK_52406, is_match_diff_52406);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52503);
        print_pairs(ptcts, 52503, MASK_52503, is_match_diff_52503);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52519);
        print_pairs(ptcts, 52519, MASK_52519, is_match_diff_52519);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52531);
        print_pairs(ptcts, 52531, MASK_52531, is_match_diff_52531);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52533);
        print_pairs(ptcts, 52533, MASK_52533, is_match_diff_52533);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52615);
        print_pairs(ptcts, 52615, MASK_52615, is_match_diff_52615);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52627);
        print_pairs(ptcts, 52627, MASK_52627, is_match_diff_52627);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52629);
        print_pairs(ptcts, 52629, MASK_52629, is_match_diff_52629);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52630);
        print_pairs(ptcts, 52630, MASK_52630, is_match_diff_52630);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52643);
        print_pairs(ptcts, 52643, MASK_52643, is_match_diff_52643);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52645);
        print_pairs(ptcts, 52645, MASK_52645, is_match_diff_52645);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52646);
        print_pairs(ptcts, 52646, MASK_52646, is_match_diff_52646);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52657);
        print_pairs(ptcts, 52657, MASK_52657, is_match_diff_52657);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52658);
        print_pairs(ptcts, 52658, MASK_52658, is_match_diff_52658);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_52660);
        print_pairs(ptcts, 52660, MASK_52660, is_match_diff_52660);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53374);
        print_pairs(ptcts, 53374, MASK_53374, is_match_diff_53374);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53566);
        print_pairs(ptcts, 53566, MASK_53566, is_match_diff_53566);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53598);
        print_pairs(ptcts, 53598, MASK_53598, is_match_diff_53598);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53614);
        print_pairs(ptcts, 53614, MASK_53614, is_match_diff_53614);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53622);
        print_pairs(ptcts, 53622, MASK_53622, is_match_diff_53622);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53626);
        print_pairs(ptcts, 53626, MASK_53626, is_match_diff_53626);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53628);
        print_pairs(ptcts, 53628, MASK_53628, is_match_diff_53628);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53822);
        print_pairs(ptcts, 53822, MASK_53822, is_match_diff_53822);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53854);
        print_pairs(ptcts, 53854, MASK_53854, is_match_diff_53854);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53870);
        print_pairs(ptcts, 53870, MASK_53870, is_match_diff_53870);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53878);
        print_pairs(ptcts, 53878, MASK_53878, is_match_diff_53878);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53882);
        print_pairs(ptcts, 53882, MASK_53882, is_match_diff_53882);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_53884);
        print_pairs(ptcts, 53884, MASK_53884, is_match_diff_53884);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54046);
        print_pairs(ptcts, 54046, MASK_54046, is_match_diff_54046);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54062);
        print_pairs(ptcts, 54062, MASK_54062, is_match_diff_54062);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54070);
        print_pairs(ptcts, 54070, MASK_54070, is_match_diff_54070);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54074);
        print_pairs(ptcts, 54074, MASK_54074, is_match_diff_54074);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54076);
        print_pairs(ptcts, 54076, MASK_54076, is_match_diff_54076);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54094);
        print_pairs(ptcts, 54094, MASK_54094, is_match_diff_54094);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54102);
        print_pairs(ptcts, 54102, MASK_54102, is_match_diff_54102);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54106);
        print_pairs(ptcts, 54106, MASK_54106, is_match_diff_54106);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54108);
        print_pairs(ptcts, 54108, MASK_54108, is_match_diff_54108);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54118);
        print_pairs(ptcts, 54118, MASK_54118, is_match_diff_54118);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54122);
        print_pairs(ptcts, 54122, MASK_54122, is_match_diff_54122);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54130);
        print_pairs(ptcts, 54130, MASK_54130, is_match_diff_54130);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54132);
        print_pairs(ptcts, 54132, MASK_54132, is_match_diff_54132);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_54136);
        print_pairs(ptcts, 54136, MASK_54136, is_match_diff_54136);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55358);
        print_pairs(ptcts, 55358, MASK_55358, is_match_diff_55358);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55390);
        print_pairs(ptcts, 55390, MASK_55390, is_match_diff_55390);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55406);
        print_pairs(ptcts, 55406, MASK_55406, is_match_diff_55406);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55414);
        print_pairs(ptcts, 55414, MASK_55414, is_match_diff_55414);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55418);
        print_pairs(ptcts, 55418, MASK_55418, is_match_diff_55418);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55420);
        print_pairs(ptcts, 55420, MASK_55420, is_match_diff_55420);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55582);
        print_pairs(ptcts, 55582, MASK_55582, is_match_diff_55582);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55598);
        print_pairs(ptcts, 55598, MASK_55598, is_match_diff_55598);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55610);
        print_pairs(ptcts, 55610, MASK_55610, is_match_diff_55610);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55612);
        print_pairs(ptcts, 55612, MASK_55612, is_match_diff_55612);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55630);
        print_pairs(ptcts, 55630, MASK_55630, is_match_diff_55630);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55638);
        print_pairs(ptcts, 55638, MASK_55638, is_match_diff_55638);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55642);
        print_pairs(ptcts, 55642, MASK_55642, is_match_diff_55642);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55644);
        print_pairs(ptcts, 55644, MASK_55644, is_match_diff_55644);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55654);
        print_pairs(ptcts, 55654, MASK_55654, is_match_diff_55654);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55658);
        print_pairs(ptcts, 55658, MASK_55658, is_match_diff_55658);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55660);
        print_pairs(ptcts, 55660, MASK_55660, is_match_diff_55660);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55666);
        print_pairs(ptcts, 55666, MASK_55666, is_match_diff_55666);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55668);
        print_pairs(ptcts, 55668, MASK_55668, is_match_diff_55668);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55672);
        print_pairs(ptcts, 55672, MASK_55672, is_match_diff_55672);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55838);
        print_pairs(ptcts, 55838, MASK_55838, is_match_diff_55838);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55854);
        print_pairs(ptcts, 55854, MASK_55854, is_match_diff_55854);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55862);
        print_pairs(ptcts, 55862, MASK_55862, is_match_diff_55862);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55866);
        print_pairs(ptcts, 55866, MASK_55866, is_match_diff_55866);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55868);
        print_pairs(ptcts, 55868, MASK_55868, is_match_diff_55868);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55886);
        print_pairs(ptcts, 55886, MASK_55886, is_match_diff_55886);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55894);
        print_pairs(ptcts, 55894, MASK_55894, is_match_diff_55894);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55900);
        print_pairs(ptcts, 55900, MASK_55900, is_match_diff_55900);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55910);
        print_pairs(ptcts, 55910, MASK_55910, is_match_diff_55910);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55914);
        print_pairs(ptcts, 55914, MASK_55914, is_match_diff_55914);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55916);
        print_pairs(ptcts, 55916, MASK_55916, is_match_diff_55916);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55922);
        print_pairs(ptcts, 55922, MASK_55922, is_match_diff_55922);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55924);
        print_pairs(ptcts, 55924, MASK_55924, is_match_diff_55924);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_55928);
        print_pairs(ptcts, 55928, MASK_55928, is_match_diff_55928);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56078);
        print_pairs(ptcts, 56078, MASK_56078, is_match_diff_56078);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56086);
        print_pairs(ptcts, 56086, MASK_56086, is_match_diff_56086);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56090);
        print_pairs(ptcts, 56090, MASK_56090, is_match_diff_56090);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56092);
        print_pairs(ptcts, 56092, MASK_56092, is_match_diff_56092);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56102);
        print_pairs(ptcts, 56102, MASK_56102, is_match_diff_56102);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56106);
        print_pairs(ptcts, 56106, MASK_56106, is_match_diff_56106);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56108);
        print_pairs(ptcts, 56108, MASK_56108, is_match_diff_56108);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56114);
        print_pairs(ptcts, 56114, MASK_56114, is_match_diff_56114);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56116);
        print_pairs(ptcts, 56116, MASK_56116, is_match_diff_56116);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56120);
        print_pairs(ptcts, 56120, MASK_56120, is_match_diff_56120);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56134);
        print_pairs(ptcts, 56134, MASK_56134, is_match_diff_56134);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56138);
        print_pairs(ptcts, 56138, MASK_56138, is_match_diff_56138);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56140);
        print_pairs(ptcts, 56140, MASK_56140, is_match_diff_56140);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56146);
        print_pairs(ptcts, 56146, MASK_56146, is_match_diff_56146);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56148);
        print_pairs(ptcts, 56148, MASK_56148, is_match_diff_56148);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56152);
        print_pairs(ptcts, 56152, MASK_56152, is_match_diff_56152);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56162);
        print_pairs(ptcts, 56162, MASK_56162, is_match_diff_56162);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56164);
        print_pairs(ptcts, 56164, MASK_56164, is_match_diff_56164);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56168);
        print_pairs(ptcts, 56168, MASK_56168, is_match_diff_56168);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_56176);
        print_pairs(ptcts, 56176, MASK_56176, is_match_diff_56176);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57527);
        print_pairs(ptcts, 57527, MASK_57527, is_match_diff_57527);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57655);
        print_pairs(ptcts, 57655, MASK_57655, is_match_diff_57655);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57751);
        print_pairs(ptcts, 57751, MASK_57751, is_match_diff_57751);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57767);
        print_pairs(ptcts, 57767, MASK_57767, is_match_diff_57767);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57779);
        print_pairs(ptcts, 57779, MASK_57779, is_match_diff_57779);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57781);
        print_pairs(ptcts, 57781, MASK_57781, is_match_diff_57781);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_57782);
        print_pairs(ptcts, 57782, MASK_57782, is_match_diff_57782);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58423);
        print_pairs(ptcts, 58423, MASK_58423, is_match_diff_58423);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58519);
        print_pairs(ptcts, 58519, MASK_58519, is_match_diff_58519);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58535);
        print_pairs(ptcts, 58535, MASK_58535, is_match_diff_58535);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58547);
        print_pairs(ptcts, 58547, MASK_58547, is_match_diff_58547);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58549);
        print_pairs(ptcts, 58549, MASK_58549, is_match_diff_58549);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58550);
        print_pairs(ptcts, 58550, MASK_58550, is_match_diff_58550);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58647);
        print_pairs(ptcts, 58647, MASK_58647, is_match_diff_58647);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58663);
        print_pairs(ptcts, 58663, MASK_58663, is_match_diff_58663);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58675);
        print_pairs(ptcts, 58675, MASK_58675, is_match_diff_58675);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58677);
        print_pairs(ptcts, 58677, MASK_58677, is_match_diff_58677);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58678);
        print_pairs(ptcts, 58678, MASK_58678, is_match_diff_58678);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58759);
        print_pairs(ptcts, 58759, MASK_58759, is_match_diff_58759);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58771);
        print_pairs(ptcts, 58771, MASK_58771, is_match_diff_58771);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58773);
        print_pairs(ptcts, 58773, MASK_58773, is_match_diff_58773);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58774);
        print_pairs(ptcts, 58774, MASK_58774, is_match_diff_58774);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58787);
        print_pairs(ptcts, 58787, MASK_58787, is_match_diff_58787);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58790);
        print_pairs(ptcts, 58790, MASK_58790, is_match_diff_58790);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58801);
        print_pairs(ptcts, 58801, MASK_58801, is_match_diff_58801);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58802);
        print_pairs(ptcts, 58802, MASK_58802, is_match_diff_58802);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_58804);
        print_pairs(ptcts, 58804, MASK_58804, is_match_diff_58804);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59447);
        print_pairs(ptcts, 59447, MASK_59447, is_match_diff_59447);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59543);
        print_pairs(ptcts, 59543, MASK_59543, is_match_diff_59543);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59559);
        print_pairs(ptcts, 59559, MASK_59559, is_match_diff_59559);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59571);
        print_pairs(ptcts, 59571, MASK_59571, is_match_diff_59571);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59573);
        print_pairs(ptcts, 59573, MASK_59573, is_match_diff_59573);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59574);
        print_pairs(ptcts, 59574, MASK_59574, is_match_diff_59574);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59671);
        print_pairs(ptcts, 59671, MASK_59671, is_match_diff_59671);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59687);
        print_pairs(ptcts, 59687, MASK_59687, is_match_diff_59687);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59699);
        print_pairs(ptcts, 59699, MASK_59699, is_match_diff_59699);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59701);
        print_pairs(ptcts, 59701, MASK_59701, is_match_diff_59701);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59783);
        print_pairs(ptcts, 59783, MASK_59783, is_match_diff_59783);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59795);
        print_pairs(ptcts, 59795, MASK_59795, is_match_diff_59795);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59797);
        print_pairs(ptcts, 59797, MASK_59797, is_match_diff_59797);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59798);
        print_pairs(ptcts, 59798, MASK_59798, is_match_diff_59798);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59811);
        print_pairs(ptcts, 59811, MASK_59811, is_match_diff_59811);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59813);
        print_pairs(ptcts, 59813, MASK_59813, is_match_diff_59813);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59814);
        print_pairs(ptcts, 59814, MASK_59814, is_match_diff_59814);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59825);
        print_pairs(ptcts, 59825, MASK_59825, is_match_diff_59825);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59826);
        print_pairs(ptcts, 59826, MASK_59826, is_match_diff_59826);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_59828);
        print_pairs(ptcts, 59828, MASK_59828, is_match_diff_59828);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60439);
        print_pairs(ptcts, 60439, MASK_60439, is_match_diff_60439);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60455);
        print_pairs(ptcts, 60455, MASK_60455, is_match_diff_60455);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60467);
        print_pairs(ptcts, 60467, MASK_60467, is_match_diff_60467);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60469);
        print_pairs(ptcts, 60469, MASK_60469, is_match_diff_60469);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60470);
        print_pairs(ptcts, 60470, MASK_60470, is_match_diff_60470);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60551);
        print_pairs(ptcts, 60551, MASK_60551, is_match_diff_60551);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60565);
        print_pairs(ptcts, 60565, MASK_60565, is_match_diff_60565);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60566);
        print_pairs(ptcts, 60566, MASK_60566, is_match_diff_60566);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60579);
        print_pairs(ptcts, 60579, MASK_60579, is_match_diff_60579);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60581);
        print_pairs(ptcts, 60581, MASK_60581, is_match_diff_60581);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60582);
        print_pairs(ptcts, 60582, MASK_60582, is_match_diff_60582);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60593);
        print_pairs(ptcts, 60593, MASK_60593, is_match_diff_60593);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60594);
        print_pairs(ptcts, 60594, MASK_60594, is_match_diff_60594);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60596);
        print_pairs(ptcts, 60596, MASK_60596, is_match_diff_60596);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60679);
        print_pairs(ptcts, 60679, MASK_60679, is_match_diff_60679);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60691);
        print_pairs(ptcts, 60691, MASK_60691, is_match_diff_60691);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60693);
        print_pairs(ptcts, 60693, MASK_60693, is_match_diff_60693);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60694);
        print_pairs(ptcts, 60694, MASK_60694, is_match_diff_60694);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60707);
        print_pairs(ptcts, 60707, MASK_60707, is_match_diff_60707);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60709);
        print_pairs(ptcts, 60709, MASK_60709, is_match_diff_60709);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60710);
        print_pairs(ptcts, 60710, MASK_60710, is_match_diff_60710);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60721);
        print_pairs(ptcts, 60721, MASK_60721, is_match_diff_60721);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60722);
        print_pairs(ptcts, 60722, MASK_60722, is_match_diff_60722);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60724);
        print_pairs(ptcts, 60724, MASK_60724, is_match_diff_60724);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60803);
        print_pairs(ptcts, 60803, MASK_60803, is_match_diff_60803);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60805);
        print_pairs(ptcts, 60805, MASK_60805, is_match_diff_60805);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60806);
        print_pairs(ptcts, 60806, MASK_60806, is_match_diff_60806);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60817);
        print_pairs(ptcts, 60817, MASK_60817, is_match_diff_60817);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60818);
        print_pairs(ptcts, 60818, MASK_60818, is_match_diff_60818);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60820);
        print_pairs(ptcts, 60820, MASK_60820, is_match_diff_60820);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60833);
        print_pairs(ptcts, 60833, MASK_60833, is_match_diff_60833);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60834);
        print_pairs(ptcts, 60834, MASK_60834, is_match_diff_60834);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60836);
        print_pairs(ptcts, 60836, MASK_60836, is_match_diff_60836);
        qsort(ptcts, 65536, sizeof(pt_ct_t), cmp_passive_60848);
        print_pairs(ptcts, 60848, MASK_60848, is_match_diff_60848);
    }

    return 0;
}

