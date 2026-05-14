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
    uint256 constant deltax1 = 21263131885293137541397055561616186802662297789970114235314442626682929864418;
    uint256 constant deltax2 = 20896384734492342693860362564755033355078892605735721180381820645040743230882;
    uint256 constant deltay1 = 579581345856929022541667398053063900792395830938587925024490109449241335979;
    uint256 constant deltay2 = 19295197284544889257513709493329399874520403328596572806151172907782538718153;

    
    uint256 constant IC0x = 20711240163280269114624405051335363667642090999610646834458637628898521986266;
    uint256 constant IC0y = 210781278586949957469934382764205776862837103395224059191484719946605763217;
    
    uint256 constant IC1x = 9215073273449707655136094790115069980476631874217318044148084432299099109330;
    uint256 constant IC1y = 3941073803192711688388408630373106937781223503783452220831780595302658813973;
    
    uint256 constant IC2x = 16782800794458808589377777171190749760827410014720646837380434849024862209065;
    uint256 constant IC2y = 20433372172009448500611873466519920457559008737496839466379467968787560729476;
    
    uint256 constant IC3x = 20511822792666994408885909344349846320624515319976336434651951882311166383582;
    uint256 constant IC3y = 21785648292391198002029437493040727851265285705821184415765953978804874023629;
    
    uint256 constant IC4x = 8867763108938382402631316299758915885774370310712481784761026388194891966132;
    uint256 constant IC4y = 11594341426345591650540616267759049245332500890767914346514088302696041324338;
    
    uint256 constant IC5x = 13247515624964781969201878406469811813758230915374566452062161190646171175237;
    uint256 constant IC5y = 3354914064546010744661785847496855639533631458881544685170155971335240487246;
    
    uint256 constant IC6x = 7653749403541672079816425824753781284133812373595201242226644355661495055853;
    uint256 constant IC6y = 7577287562561687784345778307014161105746193739398569684338684148546542280182;
    
    uint256 constant IC7x = 7837790104151588503750861585405107159206288614456550915078372943509457141891;
    uint256 constant IC7y = 10466266170309153634959661887716636012697835536260843955221986552324310947403;
    
    uint256 constant IC8x = 13001935534823061837456751174963515239004802450666588697735751325231237927743;
    uint256 constant IC8y = 7808617563479753100579180394541117528179008025273968989325659413796238316801;
    
    uint256 constant IC9x = 1745921010463818026933091043583935852988978096697214963342338650558063909243;
    uint256 constant IC9y = 18005121401296363783008342321624787848333253872122834706755428752447929158014;
    
    uint256 constant IC10x = 14868308128906834239628635610820972288769448973785248399252329193781605501294;
    uint256 constant IC10y = 20879005566805298462302130414653370841231851421144895370218100395293461470649;
    
    uint256 constant IC11x = 17560562670262227679402497162115183673092277454527870554505502035180015213104;
    uint256 constant IC11y = 7606355344654685911331105808768521133868832710386644833088019803727586956904;
    
    uint256 constant IC12x = 2175527363844343093997447026181169499936398423143195504976255127009003642872;
    uint256 constant IC12y = 9143815921994413172585874609141573105879158548934928714336824605065453732840;
    
    uint256 constant IC13x = 5723858808580680585354876065021657503483585867869357868840795804895673808763;
    uint256 constant IC13y = 20907634172772893745713467043265191806320506186650080586225066105535240587918;
    
    uint256 constant IC14x = 13146633504517024516963365817252307600187323305082415132341682216741966152201;
    uint256 constant IC14y = 9664679393403478471353665029674178453790199164994372132940038231192790639810;
    
    uint256 constant IC15x = 12663156162842784148132264618637350662710898593851333673354203048367725376804;
    uint256 constant IC15y = 3718547140606205598065784477142866749877077341420518333279550666338031425216;
    
    uint256 constant IC16x = 5283441035864960911729822246050784783933977776996086939786503021877702592757;
    uint256 constant IC16y = 1912839840537221666701508758591089276343770852049205616790437291643747434173;
    
    uint256 constant IC17x = 16605234359398344939588416021713487849645254313323950489329702713330835678624;
    uint256 constant IC17y = 7832495259160891557687144209726130763329476248662199101867264732710976366110;
    
    uint256 constant IC18x = 21740305711359998687670169691987416918983017680250534326725892186649083651448;
    uint256 constant IC18y = 6855986286336838415678885574264901204836753455843471658885707402861681743093;
    
    uint256 constant IC19x = 21396107744484311259289358856730611514997957190796988858206575650536087615602;
    uint256 constant IC19y = 713779079418685451615281153854524981919942374195014973326525363079124732127;
    
 
    // Memory data
    uint16 constant pVk = 0;
    uint16 constant pPairing = 128;

    uint16 constant pLastMem = 896;

    function verifyProof(uint[2] calldata _pA, uint[2][2] calldata _pB, uint[2] calldata _pC, uint[19] calldata _pubSignals) public view returns (bool) {
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
            

            // Validate all evaluations
            let isValid := checkPairing(_pA, _pB, _pC, _pubSignals, pMem)

            mstore(0, isValid)
             return(0, 0x20)
         }
     }
 }
