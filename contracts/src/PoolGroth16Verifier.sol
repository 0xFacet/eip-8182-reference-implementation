// SPDX-License-Identifier: GPL-3.0
/*
    Copyright 2021 0KIMS association.

    This file is generated with [snarkJS](https://github.com/iden3/snarkjs).

    snarkJS is a free software: you can redistribute it and/or modify it
    under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    snarkJS is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public
    License for more details.

    You should have received a copy of the GNU General Public License
    along with snarkJS. If not, see <https://www.gnu.org/licenses/>.
*/

pragma solidity >=0.7.0 <0.9.0;

contract PoolGroth16Verifier {
    // Scalar field size
    uint256 constant r    = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    // Base field size
    uint256 constant q   = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

    // Verification Key data
    uint256 constant alphax  = 20491192805390485299153009773594534940189261866228447918068658471970481763042;
    uint256 constant alphay  = 9383485363053290200918347156157836566562967994039712273449902621266178545958;
    uint256 constant betax1  = 4252822878758300859123897981450591353533073413197771768651442665752259397132;
    uint256 constant betax2  = 6375614351688725206403948262868962793625744043794305715222011528459656738731;
    uint256 constant betay1  = 21847035105528745403288232691147584728191162732299865338377159692350059136679;
    uint256 constant betay2  = 10505242626370262277552901082094356697409835680220590971873171140371331206856;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 21836952521369410737696191183088292853593450111941242535597408274116397048085;
    uint256 constant deltax2 = 14240917128809098946942232255372408570744298419202209331765664070807315511758;
    uint256 constant deltay1 = 16838567507774758906284664366800502290146003844386021697745045000372344683186;
    uint256 constant deltay2 = 21368636153326085825172508816811078326037274647774142029203625483793073183336;

    
    uint256 constant IC0x = 15055002528442960883936305926337935987129249116587087952310710949394502298075;
    uint256 constant IC0y = 19523770993323736607726398168359771196927296395522296844870355605469294349140;
    
    uint256 constant IC1x = 4035863800226454203673984355553870068268417999207475091945334568028302851221;
    uint256 constant IC1y = 1052561466828869242240286736751261005213216395846672281941827559260344670921;
    
    uint256 constant IC2x = 12727282839835333764076099311649403111092399785141200189709626033897901511122;
    uint256 constant IC2y = 20018305672506751156780095560092522551962194740383163532928470719597170776383;
    
    uint256 constant IC3x = 16015806444777073973084980814776974741801949827163401908286950855446883941172;
    uint256 constant IC3y = 15873358695801115514285026702118124300828554093616174915335476033573571561969;
    
    uint256 constant IC4x = 21134436275069578763545206422096425414761472812927828928787059634913088626015;
    uint256 constant IC4y = 15652891752642462930422696066087556731253423526760344491996525709820241931744;
    
    uint256 constant IC5x = 1564529156547147854100055880269840886758701217970401351930904634761131099244;
    uint256 constant IC5y = 15352971237739616952845533910884646930018545165028153215177833927241366989774;
    
    uint256 constant IC6x = 8704157116224366037325424354532531240677988801073579386899222712824257760614;
    uint256 constant IC6y = 18760192985514817046499219000066421276027597290307856758933000077830598749743;
    
    uint256 constant IC7x = 17419077034007206390495823109729318227390689746639725197955227619565217675360;
    uint256 constant IC7y = 19362686987522401728688988415681875342431578209542964158091175527023812537994;
    
    uint256 constant IC8x = 18775208107491817368776139395297735361932383674623098800593098054362037682666;
    uint256 constant IC8y = 8362390630161518797135658134289445062789889568839097281306801131849280178978;
    
    uint256 constant IC9x = 5864080987789053233836244032715490731945355219203465233230142183761233840046;
    uint256 constant IC9y = 17428760043660841046649082744615157895664059842467301288842333762099815393389;
    
    uint256 constant IC10x = 16917352129475560542044523152432854563165855781383218430973801402623378849131;
    uint256 constant IC10y = 21110192659472786470766938940296993680794423985230856632390919793814957804561;
    
    uint256 constant IC11x = 2084686631518211276061509310079726703646267545967401615305472585135327004171;
    uint256 constant IC11y = 3229319714297860352867383384999565021739304791618741506249861433990196909246;
    
    uint256 constant IC12x = 17492141460381831465948473468046750742579895367018210023034963748525810888550;
    uint256 constant IC12y = 15251121147179881101647745829978353496590670690798110115043057029959794658925;
    
    uint256 constant IC13x = 6664473166318091094110852263451198618449621833096518006100743186952737142859;
    uint256 constant IC13y = 20255738325629637473777193728975079150537287579229927271751299335109192338627;
    
    uint256 constant IC14x = 11587466116939764422758162765143448463976621248971498758987538161034705571172;
    uint256 constant IC14y = 7330941415928001400750420183057629670111970998875223254870011157294478131996;
    
    uint256 constant IC15x = 11281851002804243578011380084811190653551220980973643805116057814935696631618;
    uint256 constant IC15y = 16395777216783492909005210222541212222011541561875975497869635814458246238936;
    
    uint256 constant IC16x = 2849018238632466768907861645404282108792517472929019798148910095715667085388;
    uint256 constant IC16y = 10151701158226356587672669906703001276035692467360579961724710591006446137932;
    
    uint256 constant IC17x = 5391947111644386260618732370835001346318161796598016677549758213107492888631;
    uint256 constant IC17y = 3949225606531754239949990237816776565141285660971920115578536383931740320487;
    
    uint256 constant IC18x = 3525794634932563135661571650376027116501393517334634550119214652785690275057;
    uint256 constant IC18y = 19795254789552632680008662430315969546157115100747890726957033538622095274685;
    
    uint256 constant IC19x = 5639725300418623769846231796795571590202032393366344441816063133059635610787;
    uint256 constant IC19y = 13944472833392329343534751141249933302026316219441922300147827785614464870786;
    
    uint256 constant IC20x = 12050541280799851099161886470355914880088805913668231214691841623039729333791;
    uint256 constant IC20y = 4508811265406221196298660750773733004616256498479198746191217986140105420814;
    
    uint256 constant IC21x = 9165805418252944049230643169750462375464532673078533680529833737662362597557;
    uint256 constant IC21y = 21543525875037260863910050135508672842549101145472288462110497758444555948878;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[21] calldata _pubSignals) public view returns (bool) {
        assembly {
            function checkField(v) {
                if iszero(lt(v, r)) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }
            
            // G1 function to multiply a G1 value(x,y) to value in an address
            function g1_mulAccC(pR, x, y, s) {
                let success
                let mIn := mload(0x40)
                mstore(mIn, x)
                mstore(add(mIn, 32), y)
                mstore(add(mIn, 64), s)

                success := staticcall(sub(gas(), 2000), 7, mIn, 96, mIn, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }

                mstore(add(mIn, 64), mload(pR))
                mstore(add(mIn, 96), mload(add(pR, 32)))

                success := staticcall(sub(gas(), 2000), 6, mIn, 128, pR, 64)

                if iszero(success) {
                    mstore(0, 0)
                    return(0, 0x20)
                }
            }

            function checkPairing(pA, pB, pC, pubSignals, pMem) -> isOk {
                let _pPairing := add(pMem, pPairing)
                let _pVk := add(pMem, pVk)

                mstore(_pVk, IC0x)
                mstore(add(_pVk, 32), IC0y)

                // Compute the linear combination vk_x
                
                g1_mulAccC(_pVk, IC1x, IC1y, calldataload(add(pubSignals, 0)))
                
                g1_mulAccC(_pVk, IC2x, IC2y, calldataload(add(pubSignals, 32)))
                
                g1_mulAccC(_pVk, IC3x, IC3y, calldataload(add(pubSignals, 64)))
                
                g1_mulAccC(_pVk, IC4x, IC4y, calldataload(add(pubSignals, 96)))
                
                g1_mulAccC(_pVk, IC5x, IC5y, calldataload(add(pubSignals, 128)))
                
                g1_mulAccC(_pVk, IC6x, IC6y, calldataload(add(pubSignals, 160)))
                
                g1_mulAccC(_pVk, IC7x, IC7y, calldataload(add(pubSignals, 192)))
                
                g1_mulAccC(_pVk, IC8x, IC8y, calldataload(add(pubSignals, 224)))
                
                g1_mulAccC(_pVk, IC9x, IC9y, calldataload(add(pubSignals, 256)))
                
                g1_mulAccC(_pVk, IC10x, IC10y, calldataload(add(pubSignals, 288)))
                
                g1_mulAccC(_pVk, IC11x, IC11y, calldataload(add(pubSignals, 320)))
                
                g1_mulAccC(_pVk, IC12x, IC12y, calldataload(add(pubSignals, 352)))
                
                g1_mulAccC(_pVk, IC13x, IC13y, calldataload(add(pubSignals, 384)))
                
                g1_mulAccC(_pVk, IC14x, IC14y, calldataload(add(pubSignals, 416)))
                
                g1_mulAccC(_pVk, IC15x, IC15y, calldataload(add(pubSignals, 448)))
                
                g1_mulAccC(_pVk, IC16x, IC16y, calldataload(add(pubSignals, 480)))
                
                g1_mulAccC(_pVk, IC17x, IC17y, calldataload(add(pubSignals, 512)))
                
                g1_mulAccC(_pVk, IC18x, IC18y, calldataload(add(pubSignals, 544)))
                
                g1_mulAccC(_pVk, IC19x, IC19y, calldataload(add(pubSignals, 576)))
                
                g1_mulAccC(_pVk, IC20x, IC20y, calldataload(add(pubSignals, 608)))
                
                g1_mulAccC(_pVk, IC21x, IC21y, calldataload(add(pubSignals, 640)))
                

                // -A
                mstore(_pPairing, calldataload(pA))
                mstore(add(_pPairing, 32), mod(sub(q, calldataload(add(pA, 32))), q))

                // B
                mstore(add(_pPairing, 64), calldataload(pB))
                mstore(add(_pPairing, 96), calldataload(add(pB, 32)))
                mstore(add(_pPairing, 128), calldataload(add(pB, 64)))
                mstore(add(_pPairing, 160), calldataload(add(pB, 96)))

                // alpha1
                mstore(add(_pPairing, 192), alphax)
                mstore(add(_pPairing, 224), alphay)

                // beta2
                mstore(add(_pPairing, 256), betax1)
                mstore(add(_pPairing, 288), betax2)
                mstore(add(_pPairing, 320), betay1)
                mstore(add(_pPairing, 352), betay2)

                // vk_x
                mstore(add(_pPairing, 384), mload(add(pMem, pVk)))
                mstore(add(_pPairing, 416), mload(add(pMem, add(pVk, 32))))


                // gamma2
                mstore(add(_pPairing, 448), gammax1)
                mstore(add(_pPairing, 480), gammax2)
                mstore(add(_pPairing, 512), gammay1)
                mstore(add(_pPairing, 544), gammay2)

                // C
                mstore(add(_pPairing, 576), calldataload(pC))
                mstore(add(_pPairing, 608), calldataload(add(pC, 32)))

                // delta2
                mstore(add(_pPairing, 640), deltax1)
                mstore(add(_pPairing, 672), deltax2)
                mstore(add(_pPairing, 704), deltay1)
                mstore(add(_pPairing, 736), deltay2)


                let success := staticcall(sub(gas(), 2000), 8, _pPairing, 768, _pPairing, 0x20)

                isOk := and(success, mload(_pPairing))
            }

            let pMem := mload(0x40)
            mstore(0x40, add(pMem, pLastMem))

            // Validate that all evaluations ∈ F
            
            checkField(calldataload(add(_pubSignals, 0)))
            
            checkField(calldataload(add(_pubSignals, 32)))
            
            checkField(calldataload(add(_pubSignals, 64)))
            
            checkField(calldataload(add(_pubSignals, 96)))
            
            checkField(calldataload(add(_pubSignals, 128)))
            
            checkField(calldataload(add(_pubSignals, 160)))
            
            checkField(calldataload(add(_pubSignals, 192)))
            
            checkField(calldataload(add(_pubSignals, 224)))
            
            checkField(calldataload(add(_pubSignals, 256)))
            
            checkField(calldataload(add(_pubSignals, 288)))
            
            checkField(calldataload(add(_pubSignals, 320)))
            
            checkField(calldataload(add(_pubSignals, 352)))
            
            checkField(calldataload(add(_pubSignals, 384)))
            
            checkField(calldataload(add(_pubSignals, 416)))
            
            checkField(calldataload(add(_pubSignals, 448)))
            
            checkField(calldataload(add(_pubSignals, 480)))
            
            checkField(calldataload(add(_pubSignals, 512)))
            
            checkField(calldataload(add(_pubSignals, 544)))
            
            checkField(calldataload(add(_pubSignals, 576)))
            
            checkField(calldataload(add(_pubSignals, 608)))
            
            checkField(calldataload(add(_pubSignals, 640)))
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
