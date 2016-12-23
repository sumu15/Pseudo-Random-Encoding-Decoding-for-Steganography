function [msg] = stegandecoder(img,enc_key)
% STEGANDECODER: This function "reveals" hidden messages by reversing the
%   processing steps completed by the STEGANCODER Function.
%
% INPUTS:
% - img: This is image contains a hidden message that needs to be decoded.
% - enc_key: This is the Encryption Key used for Symmetric XOR Decryption.
%           THIS MUST BE THE SAME AS ENCRYPTION STEP FOR SUCCESSFUL 
%           DECRYPTION!
%
% OUTPUTS:
% - msg: This output file will either be a grayscale image or a hidden text
%           message that was encoded into the original image.

%% David Pipkorn and Preston Weisbrot
% Project: Steganography - Hidden Messages in Images

%% Step 1a: Recover Header Set
rm = 1; gm = 1; bm = 1;     % Initializing Counters
rn = 1; gn = 1; bn = 1;

header = [];
[maxM, maxN, chan] = size(img);

for z = 1:8;
    temp = zeros(1,8);
    % Red    
    temp(1,1) = mod(img(rm,rn,1),2);    
    rm = rm + 1;
    % This next step is used to determine whether or not we have reached
    %   the end end of the image. We then need to move to the next column
    %   and reset our pattern to the top row. Since we have no idea when we
    %   will reach this point we have to check this EVERY time after we
    %   increase the rm/gm/bm counter.
    if rm > maxM
        rn = rn + 1;
        rm = 1;
        if rn > maxN
            break
        end
    end
    % Green
    temp(1,2) = mod(img(gm,gn,2),2);
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
        if gn > maxN
            break
        end
    end
    % Blue
    temp(1,3) = mod(img(bm,bn,3),2);
    bm = bm + 1;
    if bm > maxM
        bn = bn + 1;
        bm = 1;
    end
    % Blue
    temp(1,4) = mod(img(bm,bn,3),2);
    bm = bm + 1;
    if bm > maxM
        bn = bn + 1;
        bm = 1;
    end
    % Green
    temp(1,5) = mod(img(gm,gn,2),2);
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
        if gn > maxN
            break
        end
    end
    % Red    
    temp(1,6) = mod(img(rm,rn,1),2);    
    rm = rm + 1;
    if rm > maxM
        rn = rn + 1;
        rm = 1;
        if rn > maxN
            break
        end
    end
    % Red    
    temp(1,7) = mod(img(rm,rn,1),2);    
    rm = rm + 1;
    if rm > maxM
        rn = rn + 1;
        rm = 1;
        if rn > maxN
            break
        end
    end
    % Green
    temp(1,8) = mod(img(gm,gn,2),2);
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
        if gn > maxN
            break
        end
    end      
    tempstr = num2str(temp);
    header = vertcat(header,tempstr);
end

%% Step 1b: Header Analysis - Decrypt and Determine Message Dimensions
% key = 42;  % Used for Test Phase
msg_head_set = bin2dec(header);
temp_head = bitxor(uint8(msg_head_set),uint8(enc_key));

% Case 1: If the Header starts with 't' it is a text file.
% Case 2: If the Header DOESN'T start with 't' then the message is an image
%   with the dimensions described in the header.
if temp_head(1) == 116
    % CASE 1: Text Set
    dim1 = char(temp_head(2:8));
    m = str2double(dim1);
    n = 1;    
else
    % CASE 2: Image Set
    % Determine Dimensions from Header Values
    tempm = char(temp_head(1:4));
    tempn = char(temp_head(5:8));
    m = str2double(tempm');
    n = str2double(tempn');    
end


%% Step 2: Isolate Potential Message
% Recall in Step 5 of the STEGANCODER Function we used a RGBBGRRG Cycle to
%   encode the message set. In this step we need to reverse this process
%   using MODULO arithmatic.

z = 0;

enc_msg = [];
stopmax = (m * n);

for z = 1:stopmax
    temp = zeros(1,8);
    % Red    
    temp(1,1) = mod(img(rm,rn,1),2);    
    rm = rm + 1;
    % This next step is used to determine whether or not we have reached
    %   the end end of the image. We then need to move to the next column
    %   and reset our pattern to the top row. Since we have no idea when we
    %   will reach this point we have to check this EVERY time after we
    %   increase the rm/gm/bm counter.
    if rm > maxM
        rn = rn + 1;
        rm = 1;
        if rn > maxN
            break
        end
    end
    % Green
    temp(1,2) = mod(img(gm,gn,2),2);
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
        if gn > maxN
            break
        end
    end
    % Blue
    temp(1,3) = mod(img(bm,bn,3),2);
    bm = bm + 1;
    if bm > maxM
        bn = bn + 1;
        bm = 1;
    end
    % Blue
    temp(1,4) = mod(img(bm,bn,3),2);
    bm = bm + 1;
    if bm > maxM
        bn = bn + 1;
        bm = 1;
    end
    % Green
    temp(1,5) = mod(img(gm,gn,2),2);
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
        if gn > maxN
            break
        end
    end
    % Red    
    temp(1,6) = mod(img(rm,rn,1),2);    
    rm = rm + 1;
    if rm > maxM
        rn = rn + 1;
        rm = 1;
        if rn > maxN
            break
        end
    end
    % Red    
    temp(1,7) = mod(img(rm,rn,1),2);    
    rm = rm + 1;
    if rm > maxM
        rn = rn + 1;
        rm = 1;
        if rn > maxN
            break
        end
    end
    % Green
    temp(1,8) = mod(img(gm,gn,2),2);
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
        if gn > maxN
            break
        end
    end      
    tempstr = num2str(temp);
    enc_msg = vertcat(enc_msg,tempstr);
end

%% Step 3: Decryption Step
msg_dec_set = bin2dec(enc_msg);
msg_dec = bitxor(uint8(msg_dec_set),uint8(enc_key));
% msg_dec_set = dec2bin(msg_dec,8);

%% Step 4: Message Prep
if temp_head(1) == 116
    % CASE 1: Text Set
    msg_set = msg_dec;
    msg_out = char(msg_set');
else
    % CASE 2: Image Set
    % Determine Dimensions from Header Values
    tempm = char(temp_head(1:4));
    tempn = char(temp_head(5:8));
    m = str2double(tempm');
    n = str2double(tempn');
    
    % Reshape Message Set into an Image Output
    msg_set = msg_dec;
    
    count = 1;
    msg_out = uint8(zeros(m,n));
    for y = 1:m
        for x = 1:n
            msg_out(y,x) = msg_set(count);
            count = count + 1;
        end
    end
    
    msg_out = im2uint8(msg_out);
%     THIS CODE Never worked for a larger "real" image so we scrapped it.    
%     msg_img = reshape(msg_set,m,n)';   
%     msg_out = im2uint8(msg_img);
end


%% Step 5: Final Output
msg = msg_out;
end
