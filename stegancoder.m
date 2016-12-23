function [J] = stegancoder(img,msg,enc_key)
% STEGANCODER: This function "hides" a message within an image that the
%   user provides. The final output is an image file that contains the
%   message protected by encryption and encoding.
% This function will eventually be expanded to randomly "hide" the message
%   across the "canvas" message using the STEGANCODER_RAND Function.
% 
% INPUTS:
% - img: This is the "clean" original image that will be used to hide our
%           secret message.
% - msg: This is the information to be hidden within the original image.
%           This can be a text file or another image file. Image files will
%           be converted to GRAYSCALE IMAGES.
% - enc_key: This is the Encryption Key used for Symmetric XOR Encryption.
%           THIS MUST BE THE SAME FOR SUCCESSFUL DECRYPTION!
%
% OUTPUTS:
% - J: Final image contains the encoded and/or encrypted message

%% David Pipkorn and Preston Weisbrot
% Project: Steganography - Hidden Messages in Images

%% Step 1: Determining Message Type and Normalizing
% The MATLAB Function 'double' is extremely useful for converting both
%   text files into a useful form. If the message is ASCII formatted text, 
%   double will return the integer values for each character. 
% So, 'Hello World' is: 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100
% For image files we will use 'im2unit8', which forces the pixel values to
%   be represented as integers between 0-255 (just like the text values).

msgtype = ischar(msg);  % If message is text this will be true; 
                        %   false otherwise

if msgtype == 1     % Message = TEXT
    msg_temp = double(msg);     % Converts from ASCII to Integer Values.
    msg_dim = num2str(length(msg_temp));
    msg_length = length(msg_dim);
    z = 0;
    if msg_length < 7
        padtext = 7 - msg_length;
        for z = 1:padtext
            msg_dim = horzcat('0',msg_dim);
        end
        msg_head = horzcat('t',msg_dim);
        % Applying Header To Beginning of Message to be Encoded.
        msg_temp_head = horzcat(msg_head,msg_temp);
    end
    
else
    % Message = IMAGE
    msg = im2uint8(msg);        % Convert to Integer Value Representation.
    
    msg_temp = rgb2gray(msg);   % Converts Hidden Message to Grayscale. 
                                %   Reduces Amount of Data to Hide.
                                                               
    % Determine Message Image's Size for Encoding in Header                           
    [hideM1,hideN1] = size(msg_temp);
    hideM = num2str(hideM1);
    hideN = num2str(hideN1);
    dimM = length(hideM);
    dimN = length(hideN);
    padM = 0; padN = 0;
    z = 0;
    
    if dimM < 4
        padM = 4 - dimM;
        for z = 1:padM
            % Zero Padding Dimension if less than 4 Sig Figs.
            hideM = horzcat('0',hideM);
        end
    end
    z = 0;
    
    if dimN < 4
        padN = 4 - dimN;
        for z = 1:padN
            % Zero Padding Dimension if less than 4 Sig Figs.
            hideN = horzcat('0',hideN);
        end
    end
    msg_head = horzcat(hideM,hideN);
    msg_temp_head = msg_head;
    
    y = 0;  k = hideM1;
    for y = 1:k
        % Applying Header To Beginning of Message to be Encoded.
        msg_temp_head = horzcat(msg_temp_head,msg_temp(y,:));
    end
    
end

%% Step 2: Ensuring Sufficient "Hiding Space"
% tot_hiding_pix = max(cumprod(size(img)));
% tot_data = max(cumprod(size(msg_temp_head)));
% 
% if tot_hiding_pix <= tot_data
%     error('Insufficient Hiding Space in Image')
% end

%% Step 3: Encrypting Using XOR Key
% key = 42;  % Used for Test Phase
msg_enc = bitxor(uint8(msg_temp_head),uint8(enc_key));

msg_enc_set = dec2bin(msg_enc, 8);

%% Step 4: Preparing Hiding Canvas
img_prep = im2uint8(img);


%% Step 5: Hiding Data
% I will try to hide the data points using a RGBBGRRG Order. I will be
%   hiding this data along the columns moving from left to right through
%   the target image.
rm = 1; gm = 1; bm = 1;     % Initializing Counters
rn = 1; gn = 1; bn = 1;

[maxM,maxN] = size(img_prep);
z = 0;

% RUN_TIME Variable indicates the number of Message "Words" that need to be
%   encoded in the IMG_PREP "Canvas" Image.
run_time = length(msg_enc_set);

for z = 1:run_time;
    temp_code = msg_enc_set(z,:);
    % Bit 1: Red
    if str2double(temp_code(1)) == 0
        img_prep(rm,rn,1) = bitand(img_prep(rm,rn,1),uint8(254));
    else
        img_prep(rm,rn,1) = bitor(img_prep(rm,rn,1),uint8(1));
    end
    
    rm = rm + 1;
    % This next step is used to determine whether or not we have reached
    %   the end end of the image. We then need to move to the next column
    %   and reset our pattern to the top row. Since we have no idea when we
    %   will reach this point we have to check this EVERY time after we
    %   increase the rm/gm/bm counter.
    if rm > maxM
        rn = rn + 1;
        rm = 1;
    end
    % Bit 2: Green
    if str2double(temp_code(2)) == 0
        img_prep(gm,gn,2) = bitand(img_prep(gm,gn,2),uint8(254));
    else
        img_prep(gm,gn,2) = bitor(img_prep(gm,gn,2),uint8(1));
    end
    
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
    end
    % Bit 3: Blue
    if str2double(temp_code(3)) == 0
        img_prep(bm,bn,3) = bitand(img_prep(bm,bn,3),uint8(254));
    else
        img_prep(bm,bn,3) = bitor(img_prep(bm,bn,3),uint8(1));
    end
    
    bm = bm + 1;
    if bm > maxM
        bn = bn + 1;
        bm = 1;
    end
    % Bit 4: Blue
    if str2double(temp_code(4)) == 0
        img_prep(bm,bn,3) = bitand(img_prep(bm,bn,3),uint8(254));
    else
        img_prep(bm,bn,3) = bitor(img_prep(bm,bn,3),uint8(1));
    end
    
    bm = bm + 1;
    if bm > maxM
        bn = bn + 1;
        bm = 1;
    end
    % Bit 5: Green
    if str2double(temp_code(5)) == 0
        img_prep(gm,gn,2) = bitand(img_prep(gm,gn,2),uint8(254));
    else
        img_prep(gm,gn,2) = bitor(img_prep(gm,gn,2),uint8(1));
    end
    
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
    end
    % Bit 6: Red
    if str2double(temp_code(6)) == 0
        img_prep(rm,rn,1) = bitand(img_prep(rm,rn,1),uint8(254));
    else
        img_prep(rm,rn,1) = bitor(img_prep(rm,rn,1),uint8(1));
    end
    rm = rm + 1;
    if rm > maxM
        rn = rn + 1;
        rm = 1;
    end
    % Bit 7: Red
    if str2double(temp_code(7)) == 0
        img_prep(rm,rn,1) = bitand(img_prep(rm,rn,1),uint8(254));
    else
        img_prep(rm,rn,1) = bitor(img_prep(rm,rn,1),uint8(1));
    end
    rm = rm + 1;
    if rm > maxM
        rn = rn + 1;
        rm = 1;
    end
    % Bit 8: Green
    if str2double(temp_code(8)) == 0
        img_prep(gm,gn,2) = bitand(img_prep(gm,gn,2),uint8(254));
    else
        img_prep(gm,gn,2) = bitor(img_prep(gm,gn,2),uint8(1));
    end
    
    gm = gm + 1;
    if gm > maxM
        gn = gn + 1;
        gm = 1;
    end
    
end

%% Step 6: Final Output
J = img_prep;       % Final Encoding Output
% J = msg_enc_set;  % ENCRYPTION STEP TEST OUTPUT
end