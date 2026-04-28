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
    uint256 constant alphax  = 5847872367354261624434454170970087002849476976954688950108045867744344584664;
    uint256 constant alphay  = 2951592861271585098266214058137589940338980892245074379791138387713135473365;
    uint256 constant betax1  = 12107945826896647092468155336394716655035890140774949967892862114698488831577;
    uint256 constant betax2  = 1782405132041444052142168294815102418052747308485283116574917165979465245244;
    uint256 constant betay1  = 5615078422125194690172265785513961666211239799405539529028936040655616590548;
    uint256 constant betay2  = 14443723984683310932504597207472493085288136003549154392028165777477546622039;
    uint256 constant gammax1 = 11559732032986387107991004021392285783925812861821192530917403151452391805634;
    uint256 constant gammax2 = 10857046999023057135944570762232829481370756359578518086990519993285655852781;
    uint256 constant gammay1 = 4082367875863433681332203403145435568316851327593401208105741076214120093531;
    uint256 constant gammay2 = 8495653923123431417604973247489272438418190587263600148770280649306958101930;
    uint256 constant deltax1 = 10442815686158187976238809284017041863985606675401314777601679594634287800804;
    uint256 constant deltax2 = 18399798514601554038829585913431157852925803128270121778027250842061260642661;
    uint256 constant deltay1 = 7047881070399643821833932322663153413402938316463744593343557934172025730814;
    uint256 constant deltay2 = 3003851080114752364256721877042508975651845891890227799294905687371703203325;

    
    uint256 constant IC0x = 15993756386161759186870797977191630594537121978830062059811809293920600239422;
    uint256 constant IC0y = 3351896982439868061771102037335424852673489055349868520425875267382196277555;
    
    uint256 constant IC1x = 18156724335217502185404080016050196133705273757872903050408773207103182595116;
    uint256 constant IC1y = 16970063332446261315594047951109668135998077802061488940700543150624444332111;
    
    uint256 constant IC2x = 3785876365755983757240890532808398432311458993368007976017934131962433585601;
    uint256 constant IC2y = 14173960984167764255012522893931739234176835085931052085414748702929104463489;
    
    uint256 constant IC3x = 2912023028272260068371776188022364852023762922866260475202759447823088297663;
    uint256 constant IC3y = 15337534435742323076128587300832404927103093698176083311885378176273149039274;
    
    uint256 constant IC4x = 15940140909447796464566435923743447940689814675094685313107271487423770618228;
    uint256 constant IC4y = 6894023681589238931705841322941254714724083986009882977938659060270389529412;
    
    uint256 constant IC5x = 15051030514816043617393016750076982287153231153489108000467275952224787778713;
    uint256 constant IC5y = 15315487162539041242761200778993218476412862797379586020065905716846892916132;
    
    uint256 constant IC6x = 8985116871927578487734547170573139639769644754283374266295097122586931289579;
    uint256 constant IC6y = 2030952499851110586499308541978382804580582344917514652728295086931317131123;
    
    uint256 constant IC7x = 19568810813087950192433535898037345866797194492575501083563675799986576143833;
    uint256 constant IC7y = 5190358840760582995725036294867914682579477910739274791650057737111274407441;
    
    uint256 constant IC8x = 11645610749295621733457672917157276592378398427387948267375973143234504973405;
    uint256 constant IC8y = 13581906555859853474497389072653218381965414908540533404985129102555083804365;
    
    uint256 constant IC9x = 18623490603426733680745360934374018919871689278658370809002097691006769245743;
    uint256 constant IC9y = 17027341736922401496478600408975678224180598915375891422357686909496051668670;
    
    uint256 constant IC10x = 19909950427395287286898956892390970307128918350425181739633014928021676505575;
    uint256 constant IC10y = 1823109118243723672803295157702997090206751598763188417441401793220881309694;
    
    uint256 constant IC11x = 20617824564894669534360370586141153982178627365370568131461213334752423304758;
    uint256 constant IC11y = 12031585743203268241372610324454751705518833732390523387071910421906430864398;
    
    uint256 constant IC12x = 4221809510538538881509712997897326795479878101135394221934574906145804025478;
    uint256 constant IC12y = 2109803384938396383566128726317111905049744372235701667530992882603075957687;
    
    uint256 constant IC13x = 5252737199467477054094626534698508786130354431647985915936696213195781347498;
    uint256 constant IC13y = 35357390723053796665939545427269002797329089511085067282992046339033987358;
    
    uint256 constant IC14x = 11367849086547721086841905493960490794105112798942462687960161342694632884218;
    uint256 constant IC14y = 1125108632982037447989269612120661291253324532104109972755586226172305409737;
    
    uint256 constant IC15x = 15097692810866314253913734439562877751500070651600464315187964301448059487258;
    uint256 constant IC15y = 21095452040285603243308095928356916073918827446514368223040630541404951751749;
    
    uint256 constant IC16x = 16209304016945996766534055373547040997700600101494892549479275399816170318034;
    uint256 constant IC16y = 6514071861973206642821996245990669020226840081085055694557632006443302331401;
    
    uint256 constant IC17x = 8186882254325469709835389861935310160142219400673109612450275081838248572155;
    uint256 constant IC17y = 2669520456797629780360173022810145093167368851973619435315819074412732015127;
    
    uint256 constant IC18x = 13860682833784054358071757793712043603694500697436795141489273320514723301448;
    uint256 constant IC18y = 431352677333836403495653205642959819264740724280952484919478301658845936472;
    
    uint256 constant IC19x = 10851326804248480184848216929741150729556903376102214165375978250955233518571;
    uint256 constant IC19y = 12317687294341774779801423181404967477120614436261905014165349598335078428411;
    
    uint256 constant IC20x = 16147091438419572598764405174797601086917950798956691397345966045025227205051;
    uint256 constant IC20y = 20227933538944176506131909144063710969613777288085134072963704310917291265890;
    
    uint256 constant IC21x = 11806315352244270258400114970456150592369658928503909829612057993880152027815;
    uint256 constant IC21y = 11149313667149264439333105972559812192802747658650780681236465266079986635259;
    
 
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
