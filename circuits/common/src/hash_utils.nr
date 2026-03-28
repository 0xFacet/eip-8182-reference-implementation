use poseidon::poseidon::bn254;
use crate::constants::AUTH_VK_DOMAIN;

pub fn merkle_hash2(input: [Field; 2]) -> Field {
    bn254::hash_2(input)
}

pub fn p_hash2(input: [Field; 2]) -> Field {
    merkle_hash2([2, merkle_hash2(input)])
}

pub fn p_hash3(input: [Field; 3]) -> Field {
    merkle_hash2([3, merkle_hash2([merkle_hash2([input[0], input[1]]), input[2]])])
}

pub fn p_hash4(input: [Field; 4]) -> Field {
    merkle_hash2([4, merkle_hash2([merkle_hash2([input[0], input[1]]), merkle_hash2([input[2], input[3]])])])
}

pub fn p_hash5(input: [Field; 5]) -> Field {
    merkle_hash2([
        5,
        merkle_hash2([
            merkle_hash2([merkle_hash2([input[0], input[1]]), merkle_hash2([input[2], input[3]])]),
            input[4],
        ]),
    ])
}

pub fn p_hash6(input: [Field; 6]) -> Field {
    merkle_hash2([
        6,
        merkle_hash2([
            merkle_hash2([merkle_hash2([input[0], input[1]]), merkle_hash2([input[2], input[3]])]),
            merkle_hash2([input[4], input[5]]),
        ]),
    ])
}

pub fn p_hash17(input: [Field; 17]) -> Field {
    merkle_hash2([
        17,
        merkle_hash2([
            merkle_hash2([
                merkle_hash2([
                    merkle_hash2([merkle_hash2([input[0], input[1]]), merkle_hash2([input[2], input[3]])]),
                    merkle_hash2([merkle_hash2([input[4], input[5]]), merkle_hash2([input[6], input[7]])]),
                ]),
                merkle_hash2([
                    merkle_hash2([merkle_hash2([input[8], input[9]]), merkle_hash2([input[10], input[11]])]),
                    merkle_hash2([merkle_hash2([input[12], input[13]]), merkle_hash2([input[14], input[15]])]),
                ]),
            ]),
            input[16],
        ]),
    ])
}

pub fn hash_vk(inner_vk: [Field; 115]) -> Field {
    let t0 = p_hash2([AUTH_VK_DOMAIN, 115]);
    let t1 = p_hash2([inner_vk[0], inner_vk[1]]);
    let t2 = p_hash2([t0, t1]);
    let t3 = p_hash2([inner_vk[2], inner_vk[3]]);
    let t4 = p_hash2([inner_vk[4], inner_vk[5]]);
    let t5 = p_hash2([t3, t4]);
    let t6 = p_hash2([t2, t5]);
    let t7 = p_hash2([inner_vk[6], inner_vk[7]]);
    let t8 = p_hash2([inner_vk[8], inner_vk[9]]);
    let t9 = p_hash2([t7, t8]);
    let t10 = p_hash2([inner_vk[10], inner_vk[11]]);
    let t11 = p_hash2([inner_vk[12], inner_vk[13]]);
    let t12 = p_hash2([t10, t11]);
    let t13 = p_hash2([t9, t12]);
    let t14 = p_hash2([t6, t13]);
    let t15 = p_hash2([inner_vk[14], inner_vk[15]]);
    let t16 = p_hash2([inner_vk[16], inner_vk[17]]);
    let t17 = p_hash2([t15, t16]);
    let t18 = p_hash2([inner_vk[18], inner_vk[19]]);
    let t19 = p_hash2([inner_vk[20], inner_vk[21]]);
    let t20 = p_hash2([t18, t19]);
    let t21 = p_hash2([t17, t20]);
    let t22 = p_hash2([inner_vk[22], inner_vk[23]]);
    let t23 = p_hash2([inner_vk[24], inner_vk[25]]);
    let t24 = p_hash2([t22, t23]);
    let t25 = p_hash2([inner_vk[26], inner_vk[27]]);
    let t26 = p_hash2([inner_vk[28], inner_vk[29]]);
    let t27 = p_hash2([t25, t26]);
    let t28 = p_hash2([t24, t27]);
    let t29 = p_hash2([t21, t28]);
    let t30 = p_hash2([t14, t29]);
    let t31 = p_hash2([inner_vk[30], inner_vk[31]]);
    let t32 = p_hash2([inner_vk[32], inner_vk[33]]);
    let t33 = p_hash2([t31, t32]);
    let t34 = p_hash2([inner_vk[34], inner_vk[35]]);
    let t35 = p_hash2([inner_vk[36], inner_vk[37]]);
    let t36 = p_hash2([t34, t35]);
    let t37 = p_hash2([t33, t36]);
    let t38 = p_hash2([inner_vk[38], inner_vk[39]]);
    let t39 = p_hash2([inner_vk[40], inner_vk[41]]);
    let t40 = p_hash2([t38, t39]);
    let t41 = p_hash2([inner_vk[42], inner_vk[43]]);
    let t42 = p_hash2([inner_vk[44], inner_vk[45]]);
    let t43 = p_hash2([t41, t42]);
    let t44 = p_hash2([t40, t43]);
    let t45 = p_hash2([t37, t44]);
    let t46 = p_hash2([inner_vk[46], inner_vk[47]]);
    let t47 = p_hash2([inner_vk[48], inner_vk[49]]);
    let t48 = p_hash2([t46, t47]);
    let t49 = p_hash2([inner_vk[50], inner_vk[51]]);
    let t50 = p_hash2([inner_vk[52], inner_vk[53]]);
    let t51 = p_hash2([t49, t50]);
    let t52 = p_hash2([t48, t51]);
    let t53 = p_hash2([inner_vk[54], inner_vk[55]]);
    let t54 = p_hash2([inner_vk[56], inner_vk[57]]);
    let t55 = p_hash2([t53, t54]);
    let t56 = p_hash2([inner_vk[58], inner_vk[59]]);
    let t57 = p_hash2([inner_vk[60], inner_vk[61]]);
    let t58 = p_hash2([t56, t57]);
    let t59 = p_hash2([t55, t58]);
    let t60 = p_hash2([t52, t59]);
    let t61 = p_hash2([t45, t60]);
    let t62 = p_hash2([t30, t61]);
    let t63 = p_hash2([inner_vk[62], inner_vk[63]]);
    let t64 = p_hash2([inner_vk[64], inner_vk[65]]);
    let t65 = p_hash2([t63, t64]);
    let t66 = p_hash2([inner_vk[66], inner_vk[67]]);
    let t67 = p_hash2([inner_vk[68], inner_vk[69]]);
    let t68 = p_hash2([t66, t67]);
    let t69 = p_hash2([t65, t68]);
    let t70 = p_hash2([inner_vk[70], inner_vk[71]]);
    let t71 = p_hash2([inner_vk[72], inner_vk[73]]);
    let t72 = p_hash2([t70, t71]);
    let t73 = p_hash2([inner_vk[74], inner_vk[75]]);
    let t74 = p_hash2([inner_vk[76], inner_vk[77]]);
    let t75 = p_hash2([t73, t74]);
    let t76 = p_hash2([t72, t75]);
    let t77 = p_hash2([t69, t76]);
    let t78 = p_hash2([inner_vk[78], inner_vk[79]]);
    let t79 = p_hash2([inner_vk[80], inner_vk[81]]);
    let t80 = p_hash2([t78, t79]);
    let t81 = p_hash2([inner_vk[82], inner_vk[83]]);
    let t82 = p_hash2([inner_vk[84], inner_vk[85]]);
    let t83 = p_hash2([t81, t82]);
    let t84 = p_hash2([t80, t83]);
    let t85 = p_hash2([inner_vk[86], inner_vk[87]]);
    let t86 = p_hash2([inner_vk[88], inner_vk[89]]);
    let t87 = p_hash2([t85, t86]);
    let t88 = p_hash2([inner_vk[90], inner_vk[91]]);
    let t89 = p_hash2([inner_vk[92], inner_vk[93]]);
    let t90 = p_hash2([t88, t89]);
    let t91 = p_hash2([t87, t90]);
    let t92 = p_hash2([t84, t91]);
    let t93 = p_hash2([t77, t92]);
    let t94 = p_hash2([inner_vk[94], inner_vk[95]]);
    let t95 = p_hash2([inner_vk[96], inner_vk[97]]);
    let t96 = p_hash2([t94, t95]);
    let t97 = p_hash2([inner_vk[98], inner_vk[99]]);
    let t98 = p_hash2([inner_vk[100], inner_vk[101]]);
    let t99 = p_hash2([t97, t98]);
    let t100 = p_hash2([t96, t99]);
    let t101 = p_hash2([inner_vk[102], inner_vk[103]]);
    let t102 = p_hash2([inner_vk[104], inner_vk[105]]);
    let t103 = p_hash2([t101, t102]);
    let t104 = p_hash2([inner_vk[106], inner_vk[107]]);
    let t105 = p_hash2([inner_vk[108], inner_vk[109]]);
    let t106 = p_hash2([t104, t105]);
    let t107 = p_hash2([t103, t106]);
    let t108 = p_hash2([t100, t107]);
    let t109 = p_hash2([inner_vk[110], inner_vk[111]]);
    let t110 = p_hash2([inner_vk[112], inner_vk[113]]);
    let t111 = p_hash2([t109, t110]);
    let t112 = p_hash2([t111, inner_vk[114]]);
    let t113 = p_hash2([t108, t112]);
    let t114 = p_hash2([t93, t113]);
    let t115 = p_hash2([t62, t114]);
    t115
}
